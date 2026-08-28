from __future__ import annotations

from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS = PROJECT_ROOT / "docs"
URS_ID = re.compile(r"^\| `(URS-[A-Z0-9]+-\d{3})` \|", re.MULTILINE)
RELATIVE_MARKDOWN_LINK = re.compile(r"\]\(\./([^)#]+)(?:#[^)]+)?\)")
TRACE_TEST_REFERENCE = re.compile(r"`(test_[a-z0-9_]+)::(test_[a-z0-9_]+)`")


class DocumentationContractTests(unittest.TestCase):
    def test_every_must_requirement_has_exactly_one_traceability_row(self) -> None:
        requirements = URS_ID.findall(
            (DOCS / "HUMAN_FIRST_URS.md").read_text(encoding="utf-8")
        )
        traced = URS_ID.findall(
            (DOCS / "TRACEABILITY_MATRIX.md").read_text(encoding="utf-8")
        )

        self.assertEqual(len(requirements), 29)
        self.assertEqual(len(requirements), len(set(requirements)))
        self.assertEqual(len(traced), len(set(traced)))
        self.assertEqual(set(traced), set(requirements))

    def test_local_document_links_resolve_inside_docs_directory(self) -> None:
        for path in DOCS.glob("*.md"):
            text = path.read_text(encoding="utf-8")
            for relative in RELATIVE_MARKDOWN_LINK.findall(text):
                with self.subTest(source=path.name, target=relative):
                    target = (path.parent / relative).resolve()
                    self.assertTrue(target.is_relative_to(DOCS.resolve()))
                    self.assertTrue(target.is_file())

    def test_claim_boundary_keeps_annex_22_draft_out_of_current_requirements(
        self,
    ) -> None:
        applicability = (DOCS / "REGULATORY_APPLICABILITY.md").read_text(
            encoding="utf-8"
        )
        claims = (DOCS / "CLAIMS_AND_LIMITATIONS.md").read_text(encoding="utf-8")

        self.assertIn("Annex 22", applicability)
        self.assertIn("征求意见的草案", applicability)
        self.assertIn("独立个人项目", claims)
        self.assertIn("independent personal project", claims)
        self.assertIn("不得用于批次放行", claims)

    def test_readme_local_links_resolve_inside_project(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        for relative in RELATIVE_MARKDOWN_LINK.findall(readme):
            with self.subTest(target=relative):
                target = (PROJECT_ROOT / relative).resolve()
                self.assertTrue(target.is_relative_to(PROJECT_ROOT.resolve()))
                self.assertTrue(target.is_file())

    def test_traceability_references_real_test_methods(self) -> None:
        matrix = (DOCS / "TRACEABILITY_MATRIX.md").read_text(encoding="utf-8")
        references = TRACE_TEST_REFERENCE.findall(matrix)
        self.assertGreater(len(references), 0)

        for module_name, method_name in references:
            with self.subTest(module=module_name, method=method_name):
                source = PROJECT_ROOT / "tests" / f"{module_name}.py"
                self.assertTrue(source.is_file())
                method_pattern = re.compile(
                    rf"^\s*def\s+{re.escape(method_name)}\s*\(",
                    re.MULTILINE,
                )
                self.assertRegex(source.read_text(encoding="utf-8"), method_pattern)

    PUBLIC_ENTRIES = (
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/PUBLISHING.md",
        "docs/LEARNING_00.md",
        "docs/LEARNING_ROADMAP.md",
        "docs/ASSISTED_WORKBENCH.md",
        "docs/ASSISTED_BENCHMARK.md",
        "docs/demo/WALKTHROUGH.md",
    )

    def test_public_entry_structure_and_local_links(self) -> None:
        for relative_path in self.PUBLIC_ENTRIES:
            path = PROJECT_ROOT / relative_path
            text = path.read_text(encoding="utf-8")
            prose = re.sub(r"(?ms)^ *```[^\n]*\n.*?^ *``` *$", "", text)
            with self.subTest(source=relative_path):
                self.assertEqual(len(re.findall(r"^# ", prose, re.MULTILINE)), 1)
            for relative in RELATIVE_MARKDOWN_LINK.findall(text):
                with self.subTest(source=relative_path, target=relative):
                    target = (path.parent / relative).resolve()
                    self.assertTrue(target.is_relative_to(PROJECT_ROOT.resolve()))
                    self.assertTrue(target.is_file())

    def test_public_entries_do_not_embed_machine_paths(self) -> None:
        machine_path = re.compile(r"/(?:Users|home|var/folders)/[^\s`]+")
        for relative_path in self.PUBLIC_ENTRIES:
            with self.subTest(source=relative_path):
                text = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertNotRegex(text, machine_path)

    def test_readme_does_not_link_local_run_artifacts(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        artifacts = (PROJECT_ROOT / "artifacts").resolve()
        for relative in RELATIVE_MARKDOWN_LINK.findall(readme):
            with self.subTest(target=relative):
                target = (PROJECT_ROOT / relative).resolve()
                self.assertFalse(target.is_relative_to(artifacts))

    def test_post_lock_profiles_are_not_conflated(self) -> None:
        requirements = (DOCS / "HUMAN_FIRST_URS.md").read_text(encoding="utf-8")
        scope = (DOCS / "PROJECT_SCOPE.md").read_text(encoding="utf-8")
        profiles = (DOCS / "PROCESS_PROFILES.md").read_text(encoding="utf-8")

        for text in (requirements, scope, profiles):
            self.assertIn("定向复核", text)
            self.assertIn("盲二审", text)
        self.assertIn("不得冒充 R2", requirements)
        self.assertIn("INTERVIEW_TARGETED_RECHECK", profiles)
        self.assertIn("CONSERVATIVE_BLIND_R2", profiles)
        self.assertIn("不应被称作“独立盲二审”", profiles)


if __name__ == "__main__":
    unittest.main()
