"""Opt-in local assisted review, deliberately separate from independent R1.

There is no approval or release operation. SQLite stores upload bytes, frozen
scope, candidate observations and human revisions. The local audit detects
ordinary corruption; it is not authenticated, signed or immutable storage.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
from functools import wraps
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid

from .assisted_input import (
    AssistedError,
    LOCATOR_CONFIG,
    MAX_CANDIDATES_PER_TARGET,
    MODE,
    LocalPageReader,
    candidates_from_lines,
    canonical,
    checked_box,
    crop_png,
    decode_upload,
    digest,
    exact_keys,
    integer,
    parse_target_list,
    text_value,
)


MAX_PAGES_PER_SIDE = 64
MAX_TASK_BYTES = 256 * 1024 * 1024
MAX_WORKSPACE_BYTES = 512 * 1024 * 1024
MAX_TASK_PIXELS = 512_000_000
MAX_TASK_SECONDS = 300
MAX_JOBS = 64
MAX_COMMANDS = 40_000
EMPTY_HASH = "0" * 64
COMMAND_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,96}\Z")
BINDING_KEYS = {"expected_revision", "manifest_hash", "command_id"}
HUMAN_VERDICTS = {"SAME", "DIFFERENT", "UNABLE"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def machine_status(machine: dict) -> str:
    if not machine["left"] or not machine["right"]:
        return "NOT_LOCATED"
    if machine["left_selected"] is None or machine["right_selected"] is None:
        return "MULTIPLE_CANDIDATES"
    left = machine["left"][machine["left_selected"]]
    right = machine["right"][machine["right_selected"]]
    if (
        left["problems"]
        or right["problems"]
        or not left["raw"].strip()
        or not right["raw"].strip()
    ):
        return "UNCERTAIN"
    return "SAME" if left["raw"] == right["raw"] else "DIFFERENT"


def empty_machine() -> dict:
    return {"left": [], "right": [], "left_selected": None, "right_selected": None}


def make_machine(left: list[dict], right: list[dict]) -> dict:
    return {
        "left": left,
        "right": right,
        "left_selected": 0 if len(left) == 1 else None,
        "right_selected": 0 if len(right) == 1 else None,
    }


def active_operation(method):
    """Keep the database alive while an accepted external call is in flight."""

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._activity:
            if self._closing.is_set():
                raise AssistedError("WORKSPACE_CLOSING", "工作区正在安全关闭。", 503)
            self._active_operations += 1
        try:
            return method(self, *args, **kwargs)
        finally:
            with self._activity:
                self._active_operations -= 1
                self._activity.notify_all()

    return wrapped


class AssistedWorkspace:
    """One local process owns the workspace; OCR runs sequentially and bounded."""

    def __init__(self, root: Path | str, *, reader=None) -> None:
        self.root = Path(root)
        if self.root.is_symlink():
            raise AssistedError("UNSAFE_WORKSPACE", "工作目录不能是符号链接。")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._guard = threading.RLock()
        self._ocr_gate = threading.Lock()
        self._upload_gate = threading.Lock()
        self._worker: threading.Thread | None = None
        self._closing = threading.Event()
        self._activity = threading.Condition(self._guard)
        self._active_operations = 0
        self._closed = False
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        self._lock_fd = os.open(
            self.root / "workspace.lock", os.O_RDWR | os.O_CREAT | nofollow, 0o600
        )
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._lock_fd)
            raise AssistedError("WORKSPACE_BUSY", "同一工作目录已有一个运行实例。", 409) from exc
        self._db = None
        try:
            db_path = self.root / "workspace.sqlite3"
            if db_path.is_symlink():
                raise AssistedError("UNSAFE_WORKSPACE", "数据库不能是符号链接。")
            self._db = sqlite3.connect(
                db_path, isolation_level=None, check_same_thread=False
            )
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._reader = LocalPageReader() if reader is None else reader
            self._initialize()
            for row in self._db.execute("SELECT id FROM jobs").fetchall():
                self.verify(row["id"])
            with self._transaction():
                for row in self._db.execute(
                    "SELECT id FROM jobs WHERE state='INDEXING'"
                ).fetchall():
                    self._db.execute(
                        "UPDATE jobs SET state='INTERRUPTED', error=? WHERE id=?",
                        ("上次识别中断，未将部分结果标为完成。请建立新任务。", row["id"]),
                    )
                    self._event(row["id"], "INTERRUPTED", {})
        except BaseException:
            if self._db is not None:
                self._db.close()
            os.close(self._lock_fd)
            raise

    def _initialize(self) -> None:
        if self._db.execute("PRAGMA user_version").fetchone()[0] not in (0, 1):
            raise AssistedError("UNSUPPORTED_DATABASE", "工作区版本不受支持。", 409)
        definitions = (
            "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, label TEXT NOT NULL, created TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, manifest TEXT NOT NULL, manifest_hash TEXT NOT NULL, head TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, indexed_lines INTEGER NOT NULL DEFAULT 0, error TEXT, engine_version TEXT)",
            "CREATE TABLE IF NOT EXISTS pages (id TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES jobs(id), side TEXT NOT NULL CHECK(side IN ('left','right')), descriptor TEXT NOT NULL, original BLOB NOT NULL, png BLOB NOT NULL)",
            "CREATE INDEX IF NOT EXISTS pages_job_side ON pages(job,side)",
            "CREATE TABLE IF NOT EXISTS items (job TEXT NOT NULL REFERENCES jobs(id), ordinal INTEGER NOT NULL, key TEXT NOT NULL, label TEXT NOT NULL, machine TEXT NOT NULL, status TEXT NOT NULL, human TEXT, reason TEXT NOT NULL DEFAULT '', PRIMARY KEY(job,ordinal), UNIQUE(job,key))",
            "CREATE INDEX IF NOT EXISTS items_job_status ON items(job,status,ordinal)",
            "CREATE TABLE IF NOT EXISTS events (job TEXT NOT NULL REFERENCES jobs(id), revision INTEGER NOT NULL, event TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(job,revision))",
            "CREATE TABLE IF NOT EXISTS receipts (scope TEXT NOT NULL, command_id TEXT NOT NULL, request_hash TEXT NOT NULL, response TEXT NOT NULL, PRIMARY KEY(scope,command_id))",
        )
        for sql in definitions:
            self._db.execute(sql)
        self._db.execute("PRAGMA user_version=1")

    @contextmanager
    def _transaction(self):
        with self._guard:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def _job(self, job_id: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise AssistedError("NOT_FOUND", "未找到这个本地任务。", 404)
        return row

    def _item(self, job_id: str, ordinal: int) -> sqlite3.Row:
        integer(ordinal, "条目序号", 0, 1999)
        row = self._db.execute(
            "SELECT * FROM items WHERE job=? AND ordinal=?", (job_id, ordinal)
        ).fetchone()
        if row is None:
            raise AssistedError("NOT_FOUND", "未找到这个核验项。", 404)
        return row

    def _manifest(self, job_id: str, engine_version: str | None = None) -> dict:
        targets = [
            dict(row)
            for row in self._db.execute(
                "SELECT key,label FROM items WHERE job=? ORDER BY ordinal", (job_id,)
            )
        ]
        pages = [
            json.loads(row[0])
            for row in self._db.execute(
                "SELECT descriptor FROM pages WHERE job=? ORDER BY id", (job_id,)
            )
        ]
        return {
            "mode": MODE,
            "job_id": job_id,
            "targets": targets,
            "pages": pages,
            "locator": LOCATOR_CONFIG,
            "engine_version": engine_version,
            "human_review": "all targets after AI; NOT independent R1; no release",
        }

    def _bind_manifest(self, job_id: str, engine_version: str | None = None) -> None:
        encoded = canonical(self._manifest(job_id, engine_version))
        self._db.execute(
            "UPDATE jobs SET manifest=?,manifest_hash=?,engine_version=? WHERE id=?",
            (encoded, digest(encoded.encode()), engine_version, job_id),
        )

    def _event(self, job_id: str, kind: str, payload: dict) -> dict:
        job = self._job(job_id)
        revision = job["revision"] + 1
        event = {
            "job_id": job_id,
            "mode": MODE,
            "revision": revision,
            "kind": kind,
            "at": now(),
            "manifest_hash": job["manifest_hash"],
            "payload": payload,
            "previous": job["head"],
        }
        encoded = canonical(event)
        event_hash = digest(encoded.encode())
        self._db.execute(
            "INSERT INTO events VALUES (?,?,?,?,?)",
            (job_id, revision, encoded, job["head"], event_hash),
        )
        self._db.execute(
            "UPDATE jobs SET revision=?,head=? WHERE id=?",
            (revision, event_hash, job_id),
        )
        return {
            "job_id": job_id,
            "revision": revision,
            "manifest_hash": job["manifest_hash"],
        }

    def _receipt(self, scope: str, kind: str, body: dict) -> dict | None:
        command_id = body.get("command_id")
        if type(command_id) is not str or COMMAND_PATTERN.fullmatch(command_id) is None:
            raise AssistedError("INVALID_COMMAND", "操作标识无效。")
        fingerprint = digest(canonical({"kind": kind, "body": body}).encode())
        row = self._db.execute(
            "SELECT * FROM receipts WHERE scope=? AND command_id=?", (scope, command_id)
        ).fetchone()
        if row is not None:
            if row["request_hash"] != fingerprint:
                raise AssistedError("COMMAND_CONFLICT", "同一操作标识已用于不同内容。", 409)
            return json.loads(row["response"])
        if (
            self._db.execute(
                "SELECT count(*) FROM receipts WHERE scope=?", (scope,)
            ).fetchone()[0]
            >= MAX_COMMANDS
        ):
            raise AssistedError("COMMAND_LIMIT", "任务操作数已到上限，请导出记录。", 409)
        return None

    def _save_receipt(self, scope: str, kind: str, body: dict, response: dict) -> dict:
        fingerprint = digest(canonical({"kind": kind, "body": body}).encode())
        self._db.execute(
            "INSERT INTO receipts VALUES (?,?,?,?)",
            (scope, body["command_id"], fingerprint, canonical(response)),
        )
        return response

    def _binding(self, job_id: str, body: dict, state: str) -> sqlite3.Row:
        job = self._job(job_id)
        integer(body["expected_revision"], "修订版本", 0, 1_000_000)
        if (
            body["expected_revision"] != job["revision"]
            or body["manifest_hash"] != job["manifest_hash"]
        ):
            raise AssistedError("STALE_REVISION", "数据已发生变化，请刷新后再操作。", 409)
        if job["state"] != state:
            raise AssistedError("WRONG_STAGE", "当前阶段不允许此操作。", 409)
        return job

    @active_operation
    def create(self, body: dict) -> dict:
        exact_keys(
            body,
            {
                "label",
                "targets",
                "acknowledge_assisted",
                "confirm_local_test_data",
                "confirm_single_column",
                "command_id",
            },
        )
        if any(
            body[k] is not True
            for k in (
                "acknowledge_assisted",
                "confirm_local_test_data",
                "confirm_single_column",
            )
        ):
            raise AssistedError("CONSENT_REQUIRED", "请确认辅助流程、非敏感测试图片和单列逐行布局。")
        targets = parse_target_list(body["targets"])
        label = text_value(body["label"], "任务名称", 120).strip() or "未命名核验"
        with self._transaction():
            existing = self._receipt("create", "CREATE", body)
            if existing is not None:
                return existing
            if self._db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= MAX_JOBS:
                raise AssistedError("JOB_LIMIT", "本地工作区任务已到上限，请先备份工作区。", 409)
            job_id = uuid.uuid4().hex
            self._db.execute(
                "INSERT INTO jobs(id,label,created,state,revision,manifest,manifest_hash,head) VALUES (?,?,?,'DRAFT',-1,'{}',?,?)",
                (job_id, label, now(), EMPTY_HASH, EMPTY_HASH),
            )
            self._db.executemany(
                "INSERT INTO items(job,ordinal,key,label,machine,status) VALUES (?,?,?,?,?,'PENDING')",
                [
                    (job_id, i, t["key"], t["label"], canonical(empty_machine()))
                    for i, t in enumerate(targets)
                ],
            )
            self._bind_manifest(job_id)
            return self._save_receipt(
                "create",
                "CREATE",
                body,
                self._event(job_id, "CREATE", {"targets": targets, "label": label}),
            )

    @active_operation
    def upload(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS | {"side", "name", "data"})
        if type(body["side"]) is not str or body["side"] not in {"left", "right"}:
            raise AssistedError("INVALID_SIDE", "图片只能属于照片 A 或截图 A′。")
        with self._guard:
            existing = self._receipt(job_id, "UPLOAD", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "DRAFT")
        if not self._upload_gate.acquire(blocking=False):
            raise AssistedError("BUSY", "正在处理另一张图片，请稍后再试。", 409)
        try:
            image = decode_upload(body["data"], body["name"])
            descriptor = image.descriptor()
            with self._transaction():
                existing = self._receipt(job_id, "UPLOAD", body)
                if existing is not None:
                    return existing
                self._binding(job_id, body, "DRAFT")
                current = [
                    json.loads(r[0])
                    for r in self._db.execute(
                        "SELECT descriptor FROM pages WHERE job=?", (job_id,)
                    )
                ]
                if (
                    sum(p["side"] == body["side"] for p in current)
                    >= MAX_PAGES_PER_SIDE
                ):
                    raise AssistedError("PAGE_LIMIT", "每侧最多64张图片，请分批建立任务。")
                if any(
                    p["side"] == body["side"]
                    and p["source_sha256"] == descriptor["source_sha256"]
                    for p in current
                ):
                    raise AssistedError("DUPLICATE_IMAGE", "这一侧已经有同一张图片，未重复加入。", 409)
                total = sum(p["source_bytes"] + p["png_bytes"] for p in current)
                incoming = len(image.original) + len(image.png)
                workspace_total = self._db.execute(
                    "SELECT coalesce(sum(length(original)+length(png)),0) FROM pages"
                ).fetchone()[0]
                if (
                    total + incoming > MAX_TASK_BYTES
                    or workspace_total + incoming > MAX_WORKSPACE_BYTES
                ):
                    raise AssistedError("STORAGE_LIMIT", "图片总量达到本地安全上限，请分批或建立新的备份工作区。")
                if (
                    sum(p["width"] * p["height"] for p in current)
                    + image.width * image.height
                    > MAX_TASK_PIXELS
                ):
                    raise AssistedError("PIXEL_LIMIT", "本任务累计像素超限，请分批处理。")
                page_id = uuid.uuid4().hex
                descriptor.update({"page_id": page_id, "side": body["side"]})
                self._db.execute(
                    "INSERT INTO pages VALUES (?,?,?,?,?,?)",
                    (
                        page_id,
                        job_id,
                        body["side"],
                        canonical(descriptor),
                        image.original,
                        image.png,
                    ),
                )
                self._bind_manifest(job_id)
                response = self._event(job_id, "UPLOAD", {"page": descriptor})
                response["page_id"] = page_id
                return self._save_receipt(job_id, "UPLOAD", body, response)
        finally:
            self._upload_gate.release()

    def _verified_png(self, job_id: str, page_id: str) -> tuple[dict, bytes]:
        row = self._db.execute(
            "SELECT descriptor,original,png FROM pages WHERE job=? AND id=?",
            (job_id, page_id),
        ).fetchone()
        if row is None:
            raise AssistedError("NOT_FOUND", "原图不属于此任务。", 404)
        page = json.loads(row["descriptor"])
        if (
            digest(row["original"]) != page["source_sha256"]
            or digest(row["png"]) != page["png_sha256"]
        ):
            raise AssistedError("EVIDENCE_CHANGED", "图片校验失败，已阻止继续核验。", 409)
        return page, bytes(row["png"])

    @active_operation
    def start(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS)
        with self._guard:
            existing = self._receipt(job_id, "START", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "DRAFT")
        if not self._ocr_gate.acquire(blocking=False):
            raise AssistedError("BUSY", "本机已有一个识别任务，请等它结束。", 409)
        try:
            version = text_value(self._reader.version(), "OCR 版本", 256)
            with self._transaction():
                self._binding(job_id, body, "DRAFT")
                counts = dict(
                    self._db.execute(
                        "SELECT side,count(*) FROM pages WHERE job=? GROUP BY side",
                        (job_id,),
                    ).fetchall()
                )
                if not counts.get("left") or not counts.get("right"):
                    raise AssistedError("MISSING_SIDE", "请上传照片 A 和截图 A′ 两边的图片。")
                self._bind_manifest(job_id, version)
                self._db.execute(
                    "UPDATE jobs SET state='INDEXING',error=NULL WHERE id=?", (job_id,)
                )
                response = self._event(
                    job_id,
                    "START",
                    {"pages": sum(counts.values()), "engine_version": version},
                )
                self._save_receipt(job_id, "START", body, response)
            self._worker = threading.Thread(
                target=self._index,
                args=(job_id,),
                name="paramguard-assisted-ocr",
                daemon=False,
            )
            try:
                self._worker.start()
            except Exception:
                self._worker = None
                with self._transaction():
                    self._db.execute(
                        "UPDATE jobs SET state='FAILED',error=? WHERE id=?",
                        ("识别线程未能启动，未发布结果。", job_id),
                    )
                    self._event(job_id, "FAILED", {"code": "WORKER_START_FAILED"})
                raise
            return response
        except Exception:
            self._ocr_gate.release()
            raise

    def _index(self, job_id: str) -> None:
        started = time.monotonic()
        try:
            with self._guard:
                keys = {
                    r[0]
                    for r in self._db.execute(
                        "SELECT key FROM items WHERE job=?", (job_id,)
                    )
                }
                pages = self._db.execute(
                    "SELECT id,side FROM pages WHERE job=? ORDER BY rowid", (job_id,)
                ).fetchall()
            candidates = {
                "left": {key: [] for key in keys},
                "right": {key: [] for key in keys},
            }
            for index, row in enumerate(pages):
                if (
                    self._closing.is_set()
                    or time.monotonic() - started > MAX_TASK_SECONDS
                ):
                    raise AssistedError("INTERRUPTED", "识别停止或达到任务时限，未发布部分结果。")
                with self._guard:
                    if self._job(job_id)["state"] != "INDEXING":
                        return
                    page, png = self._verified_png(job_id, row["id"])
                lines = self._reader(png, page["width"], page["height"])
                found = candidates_from_lines(lines, page, keys)
                for key, entries in found.items():
                    candidates[row["side"]][key].extend(entries)
                    if len(candidates[row["side"]][key]) > MAX_CANDIDATES_PER_TARGET:
                        raise AssistedError("CANDIDATE_LIMIT", "同一编号跨图候选过多，请分批。")
                with self._transaction():
                    if self._job(job_id)["state"] != "INDEXING":
                        return
                    self._db.execute(
                        "UPDATE jobs SET progress=?,indexed_lines=indexed_lines+? WHERE id=?",
                        (index + 1, len(lines), job_id),
                    )
                    self._event(
                        job_id,
                        "PAGE_INDEXED",
                        {"page_id": row["id"], "lines": len(lines)},
                    )
            if self._closing.is_set() or time.monotonic() - started > MAX_TASK_SECONDS:
                raise AssistedError("INTERRUPTED", "识别停止或达到任务时限，未发布部分结果。")
            with self._transaction():
                if self._job(job_id)["state"] != "INDEXING":
                    return
                hashes = {}
                for row in self._db.execute(
                    "SELECT ordinal,key FROM items WHERE job=? ORDER BY ordinal",
                    (job_id,),
                ).fetchall():
                    machine = make_machine(
                        candidates["left"][row["key"]], candidates["right"][row["key"]]
                    )
                    encoded = canonical(machine)
                    hashes[str(row["ordinal"])] = digest(encoded.encode())
                    self._db.execute(
                        "UPDATE items SET machine=?,status=? WHERE job=? AND ordinal=?",
                        (encoded, machine_status(machine), job_id, row["ordinal"]),
                    )
                self._db.execute("UPDATE jobs SET state='READY' WHERE id=?", (job_id,))
                self._event(
                    job_id,
                    "INDEXED",
                    {
                        "item_hashes": hashes,
                        "seconds": round(time.monotonic() - started, 3),
                    },
                )
        except Exception as exc:
            message = (
                exc.message
                if isinstance(exc, AssistedError)
                else "识别未能完成，未接纳部分结果；可保留此任务后重新建立任务。"
            )
            with self._transaction():
                if self._job(job_id)["state"] == "INDEXING":
                    self._db.execute(
                        "UPDATE jobs SET state='FAILED',error=? WHERE id=?",
                        (message, job_id),
                    )
                    self._event(
                        job_id,
                        "FAILED",
                        {
                            "code": exc.code
                            if isinstance(exc, AssistedError)
                            else "INTERNAL_OCR_FAILURE"
                        },
                    )
        finally:
            self._ocr_gate.release()

    @active_operation
    def cancel(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS)
        with self._transaction():
            existing = self._receipt(job_id, "CANCEL", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "INDEXING")
            self._db.execute(
                "UPDATE jobs SET state='CANCELLED',error=? WHERE id=?",
                ("已请求停止；当前单图进程会在30秒时限内收尾。未发布部分结果。", job_id),
            )
            return self._save_receipt(
                job_id, "CANCEL", body, self._event(job_id, "CANCEL", {})
            )

    def _update_machine(
        self, job_id: str, ordinal: int, machine: dict, kind: str, payload: dict
    ) -> dict:
        encoded = canonical(machine)
        self._db.execute(
            "UPDATE items SET machine=?,status=?,human=NULL,reason='' WHERE job=? AND ordinal=?",
            (encoded, machine_status(machine), job_id, ordinal),
        )
        payload = {
            **payload,
            "ordinal": ordinal,
            "machine_hash": digest(encoded.encode()),
            "invalidates_review": True,
        }
        return self._event(job_id, kind, payload)

    @active_operation
    def choose(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS | {"ordinal", "side", "candidate"})
        if type(body["side"]) is not str or body["side"] not in {"left", "right"}:
            raise AssistedError("INVALID_SIDE", "无效的图片侧别。")
        with self._transaction():
            existing = self._receipt(job_id, "CHOOSE", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "READY")
            item = self._item(job_id, body["ordinal"])
            machine = json.loads(item["machine"])
            index = integer(
                body["candidate"], "候选序号", 0, len(machine[body["side"]]) - 1
            )
            self._verified_png(job_id, machine[body["side"]][index]["page_id"])
            machine[body["side"] + "_selected"] = index
            result = self._update_machine(
                job_id,
                body["ordinal"],
                machine,
                "CHOOSE",
                {"side": body["side"], "candidate": index},
            )
            return self._save_receipt(job_id, "CHOOSE", body, result)

    @active_operation
    def region(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS | {"ordinal", "side", "page_id", "box"})
        if type(body["side"]) is not str or body["side"] not in {"left", "right"}:
            raise AssistedError("INVALID_SIDE", "无效的图片侧别。")
        with self._guard:
            existing = self._receipt(job_id, "REGION", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "READY")
            self._item(job_id, body["ordinal"])
            page, png = self._verified_png(job_id, body["page_id"])
            if page["side"] != body["side"]:
                raise AssistedError("INVALID_SIDE", "不能把另一侧的图片放入此侧。")
            box = checked_box(body["box"], page["width"], page["height"])
        if not self._ocr_gate.acquire(blocking=False):
            raise AssistedError("BUSY", "本机正在识别，请稍后再定位。", 409)
        try:
            crop = crop_png(png, box)
            lines = self._reader(crop, box[2] - box[0], box[3] - box[1])
            words = [word for line in lines for word in line["words"]]
            raw = " ".join(word["text"] for word in words)
            if len(raw) > 2048:
                raise AssistedError("REGION_TOO_LARGE", "请只框选这个参数的值和单位。")
            confidence = min((word["confidence"] for word in words), default=0)
            problems = []
            if not words:
                problems.append("NO_VALUE")
            if confidence < 70:
                problems.append("LOW_CONFIDENCE")
            if len(lines) > 1:
                problems.append("MULTILINE_REGION")
            candidate = {
                "page_id": page["page_id"],
                "name": page["name"],
                "source_sha256": page["source_sha256"],
                "png_sha256": page["png_sha256"],
                "box": box,
                "value_box": box,
                "line": None,
                "observed_id": None,
                "raw": raw,
                "confidence": confidence,
                "problems": problems,
                "method": "MANUAL_VALUE_REGION",
                "crop_sha256": digest(crop),
                "words": words,
            }
            with self._transaction():
                self._binding(job_id, body, "READY")
                self._verified_png(job_id, body["page_id"])
                machine = json.loads(self._item(job_id, body["ordinal"])["machine"])
                if len(machine[body["side"]]) >= MAX_CANDIDATES_PER_TARGET:
                    raise AssistedError("CANDIDATE_LIMIT", "该字段候选数量已到上限。")
                machine[body["side"]].append(candidate)
                machine[body["side"] + "_selected"] = len(machine[body["side"]]) - 1
                response = self._update_machine(
                    job_id,
                    body["ordinal"],
                    machine,
                    "REGION",
                    {"side": body["side"], "region": candidate},
                )
                return self._save_receipt(job_id, "REGION", body, response)
        finally:
            self._ocr_gate.release()

    @active_operation
    def review(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS | {"ordinal", "verdict", "reason"})
        verdict = body["verdict"]
        if type(verdict) is not str or verdict not in HUMAN_VERDICTS:
            raise AssistedError("INVALID_VERDICT", "人工结论只能为相同、不同或无法判断。")
        reason = text_value(body["reason"], "复核备注", 500, multiline=True)
        if verdict != "SAME" and not reason.strip():
            raise AssistedError("REASON_REQUIRED", "不同或无法判断时，请填写原因。")
        with self._transaction():
            existing = self._receipt(job_id, "REVIEW", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "READY")
            item = self._item(job_id, body["ordinal"])
            machine = json.loads(item["machine"])
            if verdict != "UNABLE" and any(
                machine[side + "_selected"] is None for side in ("left", "right")
            ):
                raise AssistedError("UNRESOLVED_LOCATION", "请先明确两侧位置，或记录为无法判断。")
            for side in ("left", "right"):
                selected = machine[side + "_selected"]
                if selected is not None:
                    self._verified_png(job_id, machine[side][selected]["page_id"])
            if verdict == "SAME" and item["status"] != "SAME" and not reason.strip():
                raise AssistedError("REASON_REQUIRED", "人工与机器提示不同，请说明依据；机器异常仍保留。")
            self._db.execute(
                "UPDATE items SET human=?,reason=? WHERE job=? AND ordinal=?",
                (verdict, reason, job_id, body["ordinal"]),
            )
            response = self._event(
                job_id,
                "REVIEW",
                {
                    "ordinal": body["ordinal"],
                    "verdict": verdict,
                    "reason": reason,
                    "actor": "local-browser-unverified-human",
                },
            )
            return self._save_receipt(job_id, "REVIEW", body, response)

    @active_operation
    def finish(self, job_id: str, body: dict) -> dict:
        exact_keys(body, BINDING_KEYS)
        with self._transaction():
            existing = self._receipt(job_id, "FINISH", body)
            if existing is not None:
                return existing
            self._binding(job_id, body, "READY")
            self.verify(job_id)
            for row in self._db.execute(
                "SELECT id FROM pages WHERE job=?", (job_id,)
            ).fetchall():
                self._verified_png(job_id, row["id"])
            if self._db.execute(
                "SELECT count(*) FROM items WHERE job=? AND human IS NULL", (job_id,)
            ).fetchone()[0]:
                raise AssistedError("REVIEW_INCOMPLETE", "每个目标都需要人工记录，机器相同不能代替人工。", 409)
            self._db.execute(
                "UPDATE jobs SET state='REVIEW_COMPLETE' WHERE id=?", (job_id,)
            )
            return self._save_receipt(
                job_id,
                "FINISH",
                body,
                self._event(
                    job_id, "FINISH", {"approval": False, "exceptions_closed": False}
                ),
            )

    @active_operation
    def jobs(self) -> list[dict]:
        with self._guard:
            return [
                dict(row)
                for row in self._db.execute(
                    "SELECT id,label,created,state FROM jobs ORDER BY rowid DESC LIMIT 64"
                )
            ]

    @active_operation
    def state(
        self,
        job_id: str,
        *,
        offset: int = 0,
        limit: int = 25,
        filter_by: str = "all",
        query: str = "",
    ) -> dict:
        integer(offset, "分页位置", 0, 2000)
        integer(limit, "每页数量", 1, 100)
        query = text_value(query, "搜索词", 128)
        allowed_filters = {
            "all",
            "pending",
            "SAME",
            "DIFFERENT",
            "UNCERTAIN",
            "NOT_LOCATED",
            "MULTIPLE_CANDIDATES",
        }
        if filter_by not in allowed_filters:
            raise AssistedError("INVALID_FILTER", "无效筛选条件。")
        with self._guard:
            job = self._job(job_id)
            rows = [
                dict(row)
                for row in self._db.execute(
                    "SELECT ordinal,key,label,status,human,reason FROM items WHERE job=? ORDER BY ordinal",
                    (job_id,),
                )
            ]
            counts = {
                status: sum(row["status"] == status for row in rows)
                for status in allowed_filters - {"all", "pending"}
            }
            reviewed = sum(row["human"] is not None for row in rows)
            filtered = [
                row
                for row in rows
                if (
                    filter_by == "all"
                    or (filter_by == "pending" and row["human"] is None)
                    or row["status"] == filter_by
                )
                and (
                    not query
                    or query.lower() in (row["key"] + " " + row["label"]).lower()
                )
            ]
            pages = [
                json.loads(row[0])
                for row in self._db.execute(
                    "SELECT descriptor FROM pages WHERE job=? ORDER BY rowid", (job_id,)
                )
            ]
            return {
                "job_id": job_id,
                "label": job["label"],
                "created": job["created"],
                "mode": MODE,
                "state": job["state"],
                "revision": job["revision"],
                "manifest_hash": job["manifest_hash"],
                "total": len(rows),
                "reviewed": reviewed,
                "remaining": len(rows) - reviewed,
                "counts": counts,
                "pages": pages,
                "progress": job["progress"],
                "indexed_lines": job["indexed_lines"],
                "error": job["error"],
                "engine_version": job["engine_version"],
                "items": filtered[offset : offset + limit],
                "filtered_total": len(filtered),
                "can_finish": job["state"] == "READY" and reviewed == len(rows),
                "approval": False,
            }

    @active_operation
    def item(self, job_id: str, ordinal: int) -> dict:
        with self._guard:
            job = self._job(job_id)
            row = dict(self._item(job_id, ordinal))
            row["machine"] = json.loads(row["machine"])
            row.update(
                {
                    "revision": job["revision"],
                    "manifest_hash": job["manifest_hash"],
                    "state": job["state"],
                }
            )
            return row

    @active_operation
    def image(self, job_id: str, page_id: str) -> bytes:
        with self._guard:
            return self._verified_png(job_id, page_id)[1]

    @active_operation
    def crop(self, job_id: str, ordinal: int, side: str, candidate: int) -> bytes:
        if side not in {"left", "right"}:
            raise AssistedError("NOT_FOUND", "未找到图块。", 404)
        with self._guard:
            machine = json.loads(self._item(job_id, ordinal)["machine"])
            integer(candidate, "候选序号", 0, len(machine[side]) - 1)
            item = machine[side][candidate]
            page, png = self._verified_png(job_id, item["page_id"])
            box = item["box"]
            padded = [
                max(0, box[0] - 12),
                max(0, box[1] - 10),
                min(page["width"], box[2] + 12),
                min(page["height"], box[3] + 10),
            ]
            return crop_png(png, padded)

    def verify(self, job_id: str) -> None:
        """Replay allowed transitions, candidate revisions and human decisions.

        Deliberately uses explicit checks, not Python assertions that disappear
        under optimization. A local writer who replaces the entire history is
        outside this unsigned journal's trust boundary.
        """

        def require(condition: bool) -> None:
            if not condition:
                raise ValueError("inconsistent assisted history")

        with self._guard:
            job = self._job(job_id)
            events = self._db.execute(
                "SELECT * FROM events WHERE job=? ORDER BY revision", (job_id,)
            ).fetchall()
            rows = self._db.execute(
                "SELECT * FROM items WHERE job=? ORDER BY ordinal", (job_id,)
            ).fetchall()
            current = {r["ordinal"]: json.loads(r["machine"]) for r in rows}
            previous, stage = EMPTY_HASH, None
            decisions, machines, pages = {}, {}, {}
            targets, version = [], None
            label, manifest, manifest_hash = None, None, None
            try:
                for revision, row in enumerate(events):
                    event = json.loads(row["event"])
                    require(row["revision"] == revision == event["revision"])
                    require(event["job_id"] == job_id and event["mode"] == MODE)
                    require(event["previous"] == row["previous"] == previous)
                    require(digest(row["event"].encode()) == row["hash"])
                    previous = row["hash"]
                    kind, payload = event["kind"], event["payload"]
                    if kind == "CREATE":
                        require(revision == 0 and stage is None)
                        targets = payload["targets"]
                        label = payload["label"]
                        machines = {i: empty_machine() for i in range(len(targets))}
                        stage = "DRAFT"
                    elif kind == "UPLOAD":
                        require(stage == "DRAFT")
                        page = payload["page"]
                        require(
                            page["page_id"] not in pages
                            and page["side"] in {"left", "right"}
                        )
                        pages[page["page_id"]] = page
                    elif kind == "START":
                        require(stage == "DRAFT" and payload["pages"] == len(pages))
                        require(
                            {p["side"] for p in pages.values()} == {"left", "right"}
                        )
                        version, stage = payload["engine_version"], "INDEXING"
                    elif kind == "PAGE_INDEXED":
                        require(stage == "INDEXING" and payload["page_id"] in pages)
                    elif kind == "INDEXED":
                        require(stage == "INDEXING")
                        require(
                            set(payload["item_hashes"]) == {str(i) for i in machines}
                        )
                        for i in machines:
                            machines[i] = make_machine(
                                [
                                    c
                                    for c in current[i]["left"]
                                    if c["method"] == "OCR_CANDIDATE"
                                ],
                                [
                                    c
                                    for c in current[i]["right"]
                                    if c["method"] == "OCR_CANDIDATE"
                                ],
                            )
                            require(
                                digest(canonical(machines[i]).encode())
                                == payload["item_hashes"][str(i)]
                            )
                        stage = "READY"
                    elif kind in {"FAILED", "INTERRUPTED", "CANCEL"}:
                        require(stage == "INDEXING")
                        stage = "CANCELLED" if kind == "CANCEL" else kind
                    elif kind in {"CHOOSE", "REGION"}:
                        require(
                            stage == "READY" and payload["invalidates_review"] is True
                        )
                        i, side = payload["ordinal"], payload["side"]
                        require(
                            type(i) is int
                            and i in machines
                            and side in {"left", "right"}
                        )
                        if kind == "REGION":
                            require(
                                payload["region"]["method"] == "MANUAL_VALUE_REGION"
                            )
                            machines[i][side].append(payload["region"])
                            selected = len(machines[i][side]) - 1
                        else:
                            selected = payload["candidate"]
                            require(
                                type(selected) is int
                                and 0 <= selected < len(machines[i][side])
                            )
                        machines[i][side + "_selected"] = selected
                        require(
                            digest(canonical(machines[i]).encode())
                            == payload["machine_hash"]
                        )
                        decisions.pop(i, None)
                    elif kind == "REVIEW":
                        require(
                            stage == "READY" and payload["verdict"] in HUMAN_VERDICTS
                        )
                        i, verdict, reason = (
                            payload["ordinal"],
                            payload["verdict"],
                            payload["reason"],
                        )
                        require(type(i) is int and i in machines)
                        if verdict != "SAME" or machine_status(machines[i]) != "SAME":
                            require(bool(reason.strip()))
                        if verdict != "UNABLE":
                            require(
                                all(
                                    machines[i][side + "_selected"] is not None
                                    for side in ("left", "right")
                                )
                            )
                        decisions[i] = (verdict, reason)
                    elif kind == "FINISH":
                        require(stage == "READY" and len(decisions) == len(targets))
                        require(
                            payload["approval"] is False
                            and payload["exceptions_closed"] is False
                        )
                        stage = "REVIEW_COMPLETE"
                    else:
                        raise ValueError("unsupported event")
                    if kind in {"CREATE", "UPLOAD", "START"}:
                        manifest = {
                            "mode": MODE,
                            "job_id": job_id,
                            "targets": targets,
                            "pages": [pages[k] for k in sorted(pages)],
                            "locator": LOCATOR_CONFIG,
                            "engine_version": version,
                            "human_review": "all targets after AI; NOT independent R1; no release",
                        }
                        manifest_hash = digest(canonical(manifest).encode())
                    require(manifest_hash == event["manifest_hash"])
                require(
                    bool(events)
                    and job["revision"] == len(events) - 1
                    and job["head"] == previous
                )
                require(job["state"] == stage and job["engine_version"] == version)
                require(job["label"] == label)
                require(
                    job["manifest"]
                    == canonical(self._manifest(job_id, version))
                    == canonical(manifest)
                )
                require(digest(job["manifest"].encode()) == job["manifest_hash"])
                require(
                    [{"key": r["key"], "label": r["label"]} for r in rows] == targets
                )
                for row in rows:
                    i = row["ordinal"]
                    require(row["machine"] == canonical(machines[i]))
                    require(
                        row["status"]
                        == (
                            machine_status(machines[i])
                            if stage in {"READY", "REVIEW_COMPLETE"}
                            else "PENDING"
                        )
                    )
                    require(
                        (row["human"], row["reason"]) == decisions.get(i, (None, ""))
                    )
                    for side in ("left", "right"):
                        for candidate in machines[i][side]:
                            page = pages[candidate["page_id"]]
                            require(page["side"] == side)
                            require(
                                candidate["source_sha256"] == page["source_sha256"]
                                and candidate["png_sha256"] == page["png_sha256"]
                            )
                            checked_box(candidate["box"], page["width"], page["height"])
            except (ValueError, KeyError, TypeError, IndexError, AssistedError) as exc:
                raise AssistedError("AUDIT_INVALID", "本地记录校验失败，未允许继续核验。", 409) from exc

    @active_operation
    def export(self, job_id: str) -> dict:
        with self._guard:
            self.verify(job_id)
            job = self._job(job_id)
            for row in self._db.execute(
                "SELECT id FROM pages WHERE job=?", (job_id,)
            ).fetchall():
                self._verified_png(job_id, row["id"])
            items = []
            for row in self._db.execute(
                "SELECT * FROM items WHERE job=? ORDER BY ordinal", (job_id,)
            ):
                item = dict(row)
                item.pop("job")
                item["machine"] = json.loads(item["machine"])
                items.append(item)
            return {
                "format": "paramguard-assisted-report-v1",
                "mode": MODE,
                "job_id": job_id,
                "label": job["label"],
                "state": job["state"],
                "created": job["created"],
                "exported": now(),
                "manifest": json.loads(job["manifest"]),
                "manifest_sha256": job["manifest_hash"],
                "audit_head": job["head"],
                "approval": False,
                "exceptions_closed": False,
                "limitations": [
                    "AI-assisted review, not independent first review",
                    "OCR IDs and values may be wrong; inspect original images",
                    "TSV spaces are reconstructed, not image whitespace truth",
                    "local reviewer is not authenticated; no signature or production validation",
                ],
                "items": items,
                "events": [
                    json.loads(r[0])
                    for r in self._db.execute(
                        "SELECT event FROM events WHERE job=? ORDER BY revision",
                        (job_id,),
                    )
                ],
            }

    def wait(self, timeout: float = 35) -> bool:
        if self._worker is not None:
            self._worker.join(timeout)
            return not self._worker.is_alive()
        return True

    def close(self) -> None:
        deadline = time.monotonic() + 40
        with self._activity:
            if self._closed:
                return
            self._closing.set()
            while self._active_operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        "accepted operations have not stopped; database left open"
                    )
                self._activity.wait(remaining)
        if not self.wait(max(0, deadline - time.monotonic())):
            raise RuntimeError("owned OCR worker has not stopped; database left open")
        with self._guard:
            if self._closed:
                return
            self._db.close()
            os.close(self._lock_fd)
            self._closed = True
