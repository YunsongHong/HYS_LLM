"""Synthetic, offline tests; no installed Tesseract or Apple framework required."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from paramguard.audit import (
    AuditAction,
    AuditIntegrityError,
    AuditPolicyError,
    JsonlAuditLog,
)
from paramguard.ocr import DEFAULT_TESSERACT_CONFIG
from tools import full_workflow_demo as demo


class FakeTsvRunner:
    """Trusted fixture used ONLY in tests, never exposed by the runtime CLI."""

    VALUES = (
        "37.0 C",
        "1.20 bar",
        "0800 rpm",
        "AUTO",
        "37.0 C",
        "1.25 bar",
        "800 rpm",
        "AUTO",
    )

    def __init__(self, fail=False):
        self.crop_calls = 0
        self.fail = fail

    def __call__(self, command, **kwargs):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, b"tesseract 5.5.1\n", b"")
        if self.fail:
            return subprocess.CompletedProcess(
                command, 2, b"", b"synthetic test failure"
            )
        text = self.VALUES[self.crop_calls]
        self.crop_calls += 1
        self.last_input = kwargs.get("input")
        tsv = (
            "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\t"
            "left\ttop\twidth\theight\tconf\ttext\n"
            f"5\t1\t1\t1\t1\t1\t10\t8\t220\t35\t95\t{text}\n"
        )
        return subprocess.CompletedProcess(command, 0, tsv.encode(), b"")


class FullWorkflowDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "new-run"

    def run_fake(self, *, fail=False):
        runner = FakeTsvRunner(fail=fail)
        engine = demo.CountingTesseractEngine(binary=sys.executable, runner=runner)
        return demo.run_demo(self.output, engine=engine), runner

    def test_full_scripted_roles_use_real_core_and_typed_audit_then_reject(self):
        report, runner = self.run_fake()
        self.assertEqual(report["status"], "COMPLETE_SAFE_REJECTION", report)
        self.assertEqual(runner.crop_calls, 8)
        self.assertEqual(report["ocr"]["returned_crop_count"], 8)
        self.assertEqual(report["ocr"]["mode"], "INJECTED_UNIT_TEST_ENGINE")
        self.assertEqual(report["ocr"]["config"], DEFAULT_TESSERACT_CONFIG.to_record())
        self.assertEqual(report["last_observed_state"], "FINAL_REJECTED")
        self.assertEqual(report["pre_final_state"], "REWORK_REQUIRED")
        self.assertEqual(report["final_decision"]["decision"], "REJECTED")
        self.assertFalse(report["actual_human_approval"])
        self.assertFalse(report["automatic_release_allowed"])
        self.assertIsNone(report["human_review_seconds"])
        self.assertTrue(report["r1_snapshot_unchanged"])
        self.assertIn("scripted demonstration", report["human_role_notice"])
        actors = report["scripted_human_actors"]
        self.assertEqual(len({actor["actor_id"] for actor in actors}), 4)
        for actor in actors:
            self.assertEqual(actor["notice"], demo.HUMAN_ROLE_NOTICE)
        log = JsonlAuditLog(self.output / "AUDIT.jsonl")
        log.verify()
        events = log.events()
        self.assertEqual(
            events[-1].action, AuditAction.TARGETED_FINAL_REJECTION_RECORDED
        )
        self.assertNotIn(
            AuditAction.TARGETED_FINAL_APPROVAL_RECORDED,
            [event.action for event in events],
        )
        self.assertIn(
            AuditAction.TARGETED_REVIEW_LOCKED, [event.action for event in events]
        )
        self.assertIn(
            AuditAction.TARGETED_QA_DISPOSITION_ACCEPTED,
            [event.action for event in events],
        )
        self.assertEqual(report["audit"]["head_sha256"], log.head_hash())
        self.assertEqual(json.loads((self.output / "REPORT.json").read_text()), report)
        for image_key in ("left_png", "right_png"):
            self.assertTrue(
                (self.output / report["evidence"][image_key])
                .read_bytes()
                .startswith(b"\x89PNG\r\n\x1a\n")
            )

    def test_denials_and_per_field_r1_precede_all_ocr(self):
        report, _ = self.run_fake()
        self.assertEqual(report["status"], "COMPLETE_SAFE_REJECTION", report)
        guards = {item["name"]: item for item in report["guard_checks"]}
        for name in (
            "prelock_ai_queue",
            "prelock_ocr",
            "prelock_result_access",
            "incomplete_r1_lock",
        ):
            self.assertTrue(guards[name]["rejected"])
            self.assertEqual(guards[name]["crop_calls_before"], 0)
            self.assertEqual(guards[name]["crop_calls_after"], 0)
        self.assertEqual(guards["approval_with_qa_blockers"]["crop_calls_after"], 8)
        r1 = [
            step for step in report["steps"] if step["operation"] == "R1_FIELD_RECORDED"
        ]
        self.assertEqual([step["completed_fields"] for step in r1], [1, 2, 3, 4])
        self.assertTrue(all(step["crop_calls"] == 0 for step in r1))
        actions = [
            event.action
            for event in JsonlAuditLog(self.output / "AUDIT.jsonl").events()
        ]
        self.assertLess(
            actions.index(AuditAction.HUMAN_REVIEW_LOCKED),
            actions.index(AuditAction.AI_REVIEW_STARTED),
        )

    def test_numeric_and_leading_zero_exceptions_are_not_resolved_away(self):
        report, _ = self.run_fake()
        self.assertEqual(report["status"], "COMPLETE_SAFE_REJECTION", report)
        by_parameter = {
            item["parameter_id"]: item for item in report["exceptions_retained"]
        }
        for parameter_id, expected in (
            ("pressure", "CONFIRMED_DIFFERENCE"),
            ("speed", "EVIDENCE_REWORK_REQUIRED"),
        ):
            exception = by_parameter[parameter_id]
            self.assertTrue(exception["qa_required"])
            disposition = report["qa_dispositions"][exception["exception_id"]]
            self.assertEqual(disposition["outcome"], expected)
            self.assertIn(demo.HUMAN_ROLE_NOTICE, disposition["rationale"])
        self.assertTrue(
            all(
                item["outcome"] != "RESOLVED_NO_BLOCKING_EXCEPTION"
                for item in report["qa_dispositions"].values()
            )
        )
        self.assertEqual(
            [
                item["parameter_id"]
                for item in report["targeted_plan"]["targeted_items"]
            ],
            ["speed"],
        )
        self.assertEqual(
            {item["parameter_id"] for item in report["targeted_plan"]["qa_referrals"]},
            {"temperature", "pressure"},
        )

    def test_existing_output_and_symlink_are_rejected_without_overwrite(self):
        self.output.mkdir()
        marker = self.output / "keep.txt"
        marker.write_text("user-owned")
        with self.assertRaises(FileExistsError):
            demo.run_demo(self.output)
        self.assertEqual(marker.read_text(), "user-owned")
        link = Path(self.temp.name) / "dangling"
        link.symlink_to(Path(self.temp.name) / "missing")
        with self.assertRaises(FileExistsError):
            demo.run_demo(link)
        self.assertTrue(link.is_symlink())

    def test_ocr_failure_stops_at_real_state_without_fabricated_final(self):
        report, _ = self.run_fake(fail=True)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["source_workflow_state"], "AI_REVIEW_COMPLETE")
        self.assertEqual(report["ocr"]["crop_attempts"], 1)
        self.assertEqual(report["ocr"]["returned_crop_count"], 0)
        self.assertNotIn("final_decision", report)
        log = JsonlAuditLog(self.output / "AUDIT.jsonl")
        log.verify()
        self.assertNotIn(
            AuditAction.TARGETED_REVIEW_LOCKED, [event.action for event in log.events()]
        )

    def test_default_constructs_unmocked_engine_and_cli_has_no_fake_option(self):
        real = demo.CountingTesseractEngine()
        self.assertEqual(real.config, DEFAULT_TESSERACT_CONFIG)
        self.assertIsNone(real._runner)
        with patch.object(
            demo, "CountingTesseractEngine", side_effect=RuntimeError("probe")
        ) as factory:
            with self.assertRaises(RuntimeError):
                demo.run_demo(self.output)
            factory.assert_called_once_with()
        with self.assertRaises(SystemExit) as error:
            demo.main(["--output", str(Path(self.temp.name) / "outside")])
        self.assertEqual(error.exception.code, 2)

    def test_rehashed_human_verdict_tamper_fails_semantic_replay(self):
        report, _ = self.run_fake()
        self.assertEqual(report["status"], "COMPLETE_SAFE_REJECTION", report)
        records = [
            json.loads(line)
            for line in (self.output / "AUDIT.jsonl").read_text().splitlines()
        ]
        for record in records:
            if (
                record["action"] == "HUMAN_DECISION_RECORDED"
                and record["parameter_id"] == "speed"
            ):
                record["details"]["verdict"] = "SAME"
                break
        previous = "0" * 64
        for record in records:
            record["previous_hash"] = previous
            body = {key: value for key, value in record.items() if key != "event_hash"}
            record["event_hash"] = hashlib.sha256(
                json.dumps(
                    body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            previous = record["event_hash"]
        tampered = self.output / "TAMPERED_TEST_ONLY.jsonl"
        tampered.write_text("".join(json.dumps(record) + "\n" for record in records))
        with self.assertRaises((AuditPolicyError, AuditIntegrityError)):
            JsonlAuditLog(tampered).verify()


if __name__ == "__main__":
    unittest.main()
