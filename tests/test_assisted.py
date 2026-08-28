import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from paramguard.assisted import AssistedWorkspace
from paramguard.assisted_input import AssistedError, parse_page_tsv
from assisted_fixtures import Reader, binding, create, png, ready, tsv, upload


class AssistedWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspace"
        self.reader = Reader()
        self.work = AssistedWorkspace(self.root, reader=self.reader)

    def tearDown(self):
        self.work.close()
        self.temp.cleanup()

    def test_explicit_opt_in_and_scope_required(self):
        for key in (
            "acknowledge_assisted",
            "confirm_local_test_data",
            "confirm_single_column",
        ):
            with self.subTest(key=key), self.assertRaises(AssistedError):
                create(self.work, **{key: 1})
        self.assertEqual(self.work.jobs(), [])

    def test_single_process_lock_and_failed_constructor_releases_lock(self):
        with self.assertRaises(AssistedError) as caught:
            AssistedWorkspace(self.root, reader=Reader())
        self.assertEqual(caught.exception.code, "WORKSPACE_BUSY")
        bad = Path(self.temp.name) / "invalid"
        bad.mkdir()
        (bad / "workspace.sqlite3").mkdir()
        for _ in range(2):
            with self.assertRaises(sqlite3.OperationalError):
                AssistedWorkspace(bad, reader=Reader())

    def test_symlink_workspace_and_database_rejected(self):
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(AssistedError):
            AssistedWorkspace(link)
        directory = Path(self.temp.name) / "bad-db"
        directory.mkdir()
        (directory / "workspace.sqlite3").symlink_to(self.root / "workspace.sqlite3")
        with self.assertRaises(AssistedError):
            AssistedWorkspace(directory)

    def test_create_and_upload_retry_and_conflict(self):
        command = "fixed-create-command"
        first = create(self.work, command_id=command)
        self.assertEqual(first, create(self.work, command_id=command))
        with self.assertRaises(AssistedError) as caught:
            create(self.work, targets="P2", command_id=command)
        self.assertEqual(caught.exception.code, "COMMAND_CONFLICT")
        job = first["job_id"]
        request = binding(
            self.work,
            job,
            side="left",
            name="synthetic.png",
            data=base64.b64encode(png()).decode(),
        )
        result = self.work.upload(job, request)
        self.assertEqual(result, self.work.upload(job, request))
        self.assertEqual(len(self.work.state(job)["pages"]), 1)
        with self.assertRaises(AssistedError) as caught:
            upload(self.work, job, "left")
        self.assertEqual(caught.exception.code, "DUPLICATE_IMAGE")

    def test_missing_side_and_stale_or_bool_revision(self):
        job = create(self.work)["job_id"]
        with self.assertRaises(AssistedError):
            self.work.start(job, binding(self.work, job))
        for version in (True, -1, 5):
            with self.subTest(version=version), self.assertRaises(AssistedError):
                upload(self.work, job, "left", expected_revision=version)
        self.assertEqual(self.reader.calls, 0)

    def test_machine_same_never_counts_as_human_or_finish(self):
        job = ready(self.work)
        state = self.work.state(job)
        self.assertEqual(
            (state["reviewed"], state["counts"]["SAME"], state["approval"]),
            (0, 1, False),
        )
        with self.assertRaises(AssistedError) as caught:
            self.work.finish(job, binding(self.work, job))
        self.assertEqual(caught.exception.code, "REVIEW_INCOMPLETE")

    def test_review_finish_restart_and_no_approval(self):
        job = ready(self.work)
        request = binding(self.work, job, ordinal=0, verdict="SAME", reason="")
        response = self.work.review(job, request)
        self.assertEqual(response, self.work.review(job, request))
        self.work.finish(job, binding(self.work, job))
        report = self.work.export(job)
        self.assertEqual(report["state"], "REVIEW_COMPLETE")
        self.assertFalse(report["approval"])
        self.assertFalse(report["exceptions_closed"])
        self.work.close()
        self.work = AssistedWorkspace(self.root, reader=Reader())
        self.assertEqual(self.work.state(job)["reviewed"], 1)
        with self.assertRaises(AssistedError):
            self.work.review(
                job, binding(self.work, job, ordinal=0, verdict="SAME", reason="")
            )

    def test_missing_and_duplicate_targets_remain_in_scope(self):
        self.reader.left = [("P1", "1.0"), ("P1", "1.0"), ("P2", "2.0")]
        self.reader.right = [("P1", "1.0")]
        job = ready(self.work, "P1\nP2\nP3")
        state = self.work.state(job)
        self.assertEqual(state["total"], 3)
        self.assertEqual(
            [i["status"] for i in state["items"]],
            ["MULTIPLE_CANDIDATES", "NOT_LOCATED", "NOT_LOCATED"],
        )
        with self.assertRaises(AssistedError):
            self.work.review(
                job,
                binding(
                    self.work, job, ordinal=1, verdict="SAME", reason="not located"
                ),
            )
        self.work.review(
            job,
            binding(
                self.work,
                job,
                ordinal=1,
                verdict="UNABLE",
                reason="SYNTHETIC missing evidence",
            ),
        )
        self.assertEqual(self.work.state(job)["counts"]["NOT_LOCATED"], 2)

    def test_human_same_does_not_clear_machine_difference(self):
        self.reader.right = [("P1", "1.25 bar")]
        job = ready(self.work)
        with self.assertRaises(AssistedError):
            self.work.review(
                job, binding(self.work, job, ordinal=0, verdict="SAME", reason="")
            )
        self.work.review(
            job,
            binding(
                self.work,
                job,
                ordinal=0,
                verdict="SAME",
                reason="SYNTHETIC disagreement test",
            ),
        )
        self.assertEqual(self.work.item(job, 0)["status"], "DIFFERENT")

    def test_concurrent_cas_one_effect_and_exact_retry(self):
        job = ready(self.work)
        requests = [
            binding(
                self.work,
                job,
                ordinal=0,
                verdict="UNABLE",
                reason="synthetic concurrency",
            )
            for _ in range(2)
        ]

        def submit(body):
            try:
                return self.work.review(job, body)
            except AssistedError as exc:
                return exc.code

        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(submit, requests))
        self.assertEqual(sum(isinstance(r, dict) for r in results), 1)
        self.assertIn("STALE_REVISION", results)
        index = next(i for i, result in enumerate(results) if isinstance(result, dict))
        self.assertEqual(self.work.review(job, requests[index]), results[index])

    def test_manual_region_invalidates_only_current_human_preserves_history(self):
        job = ready(self.work)
        self.work.review(
            job, binding(self.work, job, ordinal=0, verdict="SAME", reason="")
        )
        self.reader.__class__ = RegionReader
        page = next(p for p in self.work.state(job)["pages"] if p["side"] == "left")
        self.work.region(
            job,
            binding(
                self.work,
                job,
                ordinal=0,
                side="left",
                page_id=page["page_id"],
                box=[0, 0, 600, 100],
            ),
        )
        report = self.work.export(job)
        self.assertIsNone(report["items"][0]["human"])
        self.assertEqual(
            report["items"][0]["machine"]["left"][-1]["method"], "MANUAL_VALUE_REGION"
        )
        self.assertTrue(any(e["kind"] == "REVIEW" for e in report["events"]))
        self.work.close()
        self.work = AssistedWorkspace(self.root, reader=Reader())
        self.assertEqual(self.work.state(job)["reviewed"], 0)

    def test_choose_candidate_is_audited_and_does_not_auto_review(self):
        self.reader.left = [("P1", "1.0"), ("P1", "2.0")]
        self.reader.right = [("P1", "1.0")]
        job = ready(self.work)
        self.work.choose(
            job, binding(self.work, job, ordinal=0, side="left", candidate=0)
        )
        self.assertEqual(self.work.state(job)["reviewed"], 0)
        self.work.verify(job)

    def test_cross_job_and_wrong_side_evidence_rejected(self):
        job = ready(self.work)
        other = create(self.work)["job_id"]
        page = self.work.state(job)["pages"][0]
        with self.assertRaises(AssistedError):
            self.work.image(other, page["page_id"])
        with self.assertRaises(AssistedError):
            self.work.region(
                job,
                binding(
                    self.work,
                    job,
                    ordinal=0,
                    side="right",
                    page_id=page["page_id"],
                    box=[0, 0, 100, 100],
                ),
            )

    def test_upload_after_index_is_rejected_without_replacing_records(self):
        job = ready(self.work)
        before = self.work.export(job)
        with self.assertRaises(AssistedError):
            upload(self.work, job, "left", png("red"))
        self.assertEqual(before["audit_head"], self.work.export(job)["audit_head"])

    def test_finish_rejects_forged_human_projection(self):
        job = ready(self.work)
        self.work._db.execute("UPDATE items SET human='SAME' WHERE job=?", (job,))
        with self.assertRaises(AssistedError) as caught:
            self.work.finish(job, binding(self.work, job))
        self.assertEqual(caught.exception.code, "AUDIT_INVALID")
        self.assertEqual(self.work.state(job)["state"], "READY")

    def test_finish_checks_actual_image_bytes(self):
        job = ready(self.work)
        self.work.review(
            job, binding(self.work, job, ordinal=0, verdict="SAME", reason="")
        )
        self.work._db.execute("UPDATE pages SET png=? WHERE job=?", (b"tampered", job))
        with self.assertRaises(AssistedError) as caught:
            self.work.finish(job, binding(self.work, job))
        self.assertEqual(caught.exception.code, "EVIDENCE_CHANGED")
        self.assertEqual(self.work.state(job)["state"], "READY")

    def test_label_and_candidate_projection_corruption_detected(self):
        job = ready(self.work)
        self.work._db.execute("UPDATE jobs SET label='wrong' WHERE id=?", (job,))
        with self.assertRaises(AssistedError):
            self.work.export(job)

    def test_ocr_failure_does_not_publish_partial_candidates(self):
        def fail(*args):
            raise RuntimeError("synthetic failure")

        self.work._reader = type(
            "FailReader", (), {"version": lambda s: "test", "__call__": fail}
        )()
        job = create(self.work, "P1\nP2")["job_id"]
        upload(self.work, job, "left")
        upload(self.work, job, "right")
        self.work.start(job, binding(self.work, job))
        self.assertTrue(self.work.wait(5))
        state = self.work.state(job)
        self.assertEqual(
            (state["state"], state["total"], state["reviewed"]), ("FAILED", 2, 0)
        )
        self.work.verify(job)

    def test_close_waits_for_accepted_region_reader(self):
        job = ready(self.work)
        page = self.work.state(job)["pages"][0]
        entered, release, closed = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )

        class BlockedReader(RegionReader):
            def __call__(self, *args):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test release missing")
                return super().__call__(*args)

        self.work._reader = BlockedReader()
        body = binding(
            self.work,
            job,
            ordinal=0,
            side="left",
            page_id=page["page_id"],
            box=[0, 0, 600, 100],
        )
        with ThreadPoolExecutor(2) as pool:
            operation = pool.submit(self.work.region, job, body)
            self.assertTrue(entered.wait(2))

            def close():
                self.work.close()
                closed.set()

            closing = pool.submit(close)
            self.assertFalse(closed.wait(0.05))
            release.set()
            operation.result(5)
            closing.result(5)
        self.assertTrue(closed.is_set())
        self.work = AssistedWorkspace(self.root, reader=Reader())
        self.work.verify(job)

    def test_6000_synthetic_tsv_rows_keep_1000_targets_and_require_all_reviews(self):
        # This exercises scope and persistence, not real OCR/image accuracy.
        source = [tsv([]).strip()]
        for i in range(6000):
            key = f"P{i:06d}"
            source.append(f"5\t1\t1\t1\t{i+1}\t1\t10\t{i*2+1}\t100\t1\t95\t{key}")
            source.append(f"5\t1\t1\t1\t{i+1}\t2\t150\t{i*2+1}\t100\t1\t95\t42.00")
        source = "\n".join(source) + "\n"

        class ScaleReader(Reader):
            def __call__(self, image, width, height):
                return parse_page_tsv(source, width, height)

        self.work._reader = ScaleReader()
        targets = "\n".join(f"P{i:06d}" for i in range(0, 6000, 6))
        job = ready(self.work, targets, size=(700, 12020))
        state = self.work.state(job)
        self.assertEqual(
            (state["total"], state["reviewed"], state["counts"]["SAME"]),
            (1000, 0, 1000),
        )
        self.assertEqual(len(state["items"]), 25)
        self.assertEqual(len(self.work.state(job, offset=975)["items"]), 25)
        for ordinal in range(999):
            self.work.review(
                job, binding(self.work, job, ordinal=ordinal, verdict="SAME", reason="")
            )
        with self.assertRaises(AssistedError) as caught:
            self.work.finish(job, binding(self.work, job))
        self.assertEqual(caught.exception.code, "REVIEW_INCOMPLETE")
        self.work.review(
            job, binding(self.work, job, ordinal=999, verdict="SAME", reason="")
        )
        self.work.finish(job, binding(self.work, job))
        self.work.close()
        self.work = AssistedWorkspace(self.root, reader=Reader())
        report = self.work.export(job)
        self.assertEqual(len(report["items"]), 1000)
        self.assertEqual(self.work.state(job)["reviewed"], 1000)
        self.assertFalse(report["approval"])


class RegionReader(Reader):
    def __call__(self, image, width, height):
        # Only a value in the explicitly selected synthetic region.
        return parse_page_tsv(tsv([("1.20", "bar")]), width, height)


if __name__ == "__main__":
    unittest.main()
