from __future__ import annotations

from contextlib import closing
import ast
import hashlib
import inspect
from pathlib import Path
import tempfile
import unittest

from paramguard import db
from paramguard.db import (
    Migration,
    MigrationError,
    connect_database,
    load_packaged_migrations,
    migrate_database,
    verify_database_integrity,
)


class SQLiteMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "paramguard.db"

    def test_packaged_migration_checksum_and_user_version_are_consistent(self) -> None:
        migrations = load_packaged_migrations()
        self.assertEqual(tuple(item.version for item in migrations), (1, 2))
        self.assertEqual(migrations[0].name, "0001_initial.sql")
        self.assertEqual(migrations[1].name, "0002_r1_lock_revision_scope.sql")
        for migration in migrations:
            self.assertEqual(
                migration.sha256,
                hashlib.sha256(migration.sql.encode("utf-8")).hexdigest(),
            )
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(migrate_database(connection), 2)
            rows = connection.execute(
                "SELECT version, name, sha256 FROM _paramguard_migrations"
                " ORDER BY version"
            ).fetchall()
            self.assertEqual(
                tuple(tuple(row) for row in rows),
                tuple(
                    (migration.version, migration.name, migration.sha256)
                    for migration in migrations
                ),
            )
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_migration_engine_never_uses_executescript(self) -> None:
        source = inspect.getsource(db.migrate_database) + inspect.getsource(
            db._split_sql_statements  # type: ignore[attr-defined]
        )
        tree = ast.parse(source)
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("executescript", called_attributes)

    def test_failed_migration_is_all_or_nothing(self) -> None:
        sql = """
CREATE TABLE _paramguard_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE would_have_existed(value TEXT) STRICT;
THIS IS NOT SQL;
"""
        migration = Migration(
            version=1,
            name="0001_broken.sql",
            sql=sql,
            sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
        )
        with closing(connect_database(self.path)) as connection:
            with self.assertRaises(Exception):
                migrate_database(connection, migrations=(migration,))
            names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                )
            }
            self.assertNotIn("_paramguard_migrations", names)
            self.assertNotIn("would_have_existed", names)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)

    def test_migration_commit_busy_rolls_back_schema_and_ledger(self) -> None:
        with (
            closing(connect_database(self.path, busy_timeout_ms=25)) as migrator,
            closing(connect_database(self.path, busy_timeout_ms=25)) as reader,
        ):
            reader.execute("BEGIN")
            reader.execute("SELECT name FROM main.sqlite_schema").fetchall()
            with self.assertRaisesRegex(Exception, "locked"):
                migrate_database(migrator)
            self.assertFalse(migrator.in_transaction)
            self.assertEqual(migrator.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertNotIn(
                "_paramguard_migrations",
                {
                    row[0]
                    for row in migrator.execute(
                        "SELECT name FROM main.sqlite_schema WHERE type='table'"
                    )
                },
            )
            reader.execute("ROLLBACK")
            self.assertEqual(migrate_database(migrator), 2)
            self.assertEqual(verify_database_integrity(migrator).user_version, 2)

    def test_user_version_drift_and_checksum_tamper_fail_closed(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute("PRAGMA user_version=0")
            with self.assertRaisesRegex(MigrationError, "user_version"):
                migrate_database(connection)
            connection.execute("PRAGMA user_version=1")
            connection.execute("DROP TRIGGER migrations_no_update")
            connection.execute(
                "UPDATE _paramguard_migrations SET sha256=? WHERE version=1",
                ("f" * 64,),
            )
            with self.assertRaisesRegex(MigrationError, "checksum"):
                migrate_database(connection)

    def test_every_required_domain_table_is_strict_and_migration_is_idempotent(
        self,
    ) -> None:
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(migrate_database(connection), 2)
            self.assertEqual(migrate_database(connection), 2)
            verify_database_integrity(connection)
            strict_by_name = {
                row[1]: row[5] for row in connection.execute("PRAGMA table_list")
            }
        expected = {
            "tasks",
            "task_parameters",
            "evidence_artifacts",
            "task_assignments",
            "r1_decisions",
            "r1_locks",
            "command_receipts",
            "audit_outbox",
        }
        self.assertTrue(all(strict_by_name.get(name) == 1 for name in expected))

    def test_lock_scope_migration_preserves_existing_lock_rows(self) -> None:
        migrations = load_packaged_migrations()
        hash_value = "a" * 64
        timestamp = "2026-08-27T00:00:00.000000Z"
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                migrate_database(connection, migrations=(migrations[0],)), 1
            )
            connection.execute(
                "INSERT INTO tasks VALUES "
                "('TASK-A','STRICT_SEQUENTIAL','HUMAN_REVIEW_OPEN',0,'SYNTHETIC',"
                "'manifest',?,?, 'pipeline',?,?,?,NULL)",
                (hash_value, "{}", hash_value, "{}", timestamp),
            )
            connection.execute(
                "INSERT INTO task_parameters VALUES ('TASK-A',0,'parameter')"
            )
            connection.execute(
                "INSERT INTO task_assignments VALUES "
                "('TASK-A','R1','reviewer-A','R1_REVIEWER',?)",
                (timestamp,),
            )
            connection.execute(
                "INSERT INTO r1_decisions VALUES "
                "('TASK-A','parameter',1,1,'SAME',NULL,'reviewer-A',?,?,"
                "'decision-A')",
                (hash_value, timestamp),
            )
            connection.execute("UPDATE tasks SET revision=1 WHERE task_id='TASK-A'")
            connection.execute(
                "INSERT INTO r1_locks VALUES "
                "('TASK-A',2,1,?,?,'reviewer-A',?,'lock-A')",
                (hash_value, hash_value, timestamp),
            )
            connection.execute(
                "UPDATE tasks SET state='HUMAN_REVIEW_LOCKED', revision=2, "
                "r1_locked_at=? WHERE task_id='TASK-A'",
                (timestamp,),
            )

            self.assertEqual(migrate_database(connection), 2)
            row = connection.execute(
                "SELECT task_id, task_revision, command_id FROM r1_locks"
            ).fetchone()
            self.assertEqual(tuple(row), ("TASK-A", 2, "lock-A"))
            verify_database_integrity(connection)


if __name__ == "__main__":
    unittest.main()
