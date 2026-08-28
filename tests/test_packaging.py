from __future__ import annotations

from importlib import resources
from pathlib import Path
import tomllib
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PackagingContractTests(unittest.TestCase):
    def test_python_and_runtime_dependency_contract_is_explicit(self) -> None:
        payload = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertEqual(payload["project"]["requires-python"], ">=3.11")
        self.assertEqual(payload["project"]["dependencies"], ["Pillow>=10.1,<13"])

    def test_web_template_is_declared_as_package_data(self) -> None:
        payload = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        package_data = payload["tool"]["setuptools"]["package-data"]

        self.assertIn("static/*.html", package_data["paramguard"])
        for filename in ("paramguard.html", "assisted.html"):
            with self.subTest(template=filename):
                packaged_template = resources.files("paramguard").joinpath(
                    "static", filename
                )
                self.assertTrue(packaged_template.is_file())

    def test_sqlite_migrations_are_declared_as_package_data(self) -> None:
        payload = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        package_data = payload["tool"]["setuptools"]["package-data"]

        self.assertIn("migrations/*.sql", package_data["paramguard"])
        migration = resources.files("paramguard").joinpath(
            "migrations", "0002_r1_lock_revision_scope.sql"
        )
        self.assertTrue(migration.is_file())


if __name__ == "__main__":
    unittest.main()
