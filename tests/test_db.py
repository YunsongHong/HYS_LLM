from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from paramguard.db import (
    DatabaseIntegrityError,
    SQLiteCapabilityError,
    SQLiteConfigurationError,
    connect_database,
    consistent_read_transaction,
    immediate_transaction,
    load_packaged_migrations,
    migrate_database,
    require_sqlite_capabilities,
    verify_database_integrity,
    wal_reset_fix_present,
)


class DatabaseConnectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "paramguard.db"

    def test_connection_factory_uses_explicit_autocommit_and_verified_pragmas(
        self,
    ) -> None:
        with closing(connect_database(self.path)) as connection:
            self.assertIsNone(connection.isolation_level)
            self.assertFalse(connection.in_transaction)
            self.assertEqual(
                connection.execute("PRAGMA journal_mode").fetchone()[0], "delete"
            )
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 3)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000
            )
            self.assertEqual(
                connection.execute("PRAGMA trusted_schema").fetchone()[0], 0
            )

    def test_immediate_transaction_commits_or_rolls_back_as_one_unit(self) -> None:
        with closing(connect_database(self.path)) as connection:
            connection.execute("CREATE TABLE sample(value TEXT) STRICT")
            with immediate_transaction(connection):
                connection.execute("INSERT INTO sample VALUES ('committed')")
            with self.assertRaisesRegex(RuntimeError, "fault"):
                with immediate_transaction(connection):
                    connection.execute("INSERT INTO sample VALUES ('rolled-back')")
                    raise RuntimeError("fault")
            self.assertEqual(
                [row[0] for row in connection.execute("SELECT value FROM sample")],
                ["committed"],
            )

    def test_owned_transactions_roll_back_when_commit_is_busy(self) -> None:
        for transaction in (immediate_transaction, consistent_read_transaction):
            with self.subTest(transaction=transaction.__name__):
                path = Path(self.temporary.name) / f"{transaction.__name__}-busy.db"
                with (
                    closing(connect_database(path, busy_timeout_ms=25)) as writer,
                    closing(connect_database(path, busy_timeout_ms=25)) as reader,
                ):
                    writer.execute("CREATE TABLE sample(value TEXT) STRICT")
                    reader.execute("BEGIN")
                    reader.execute("SELECT * FROM sample").fetchall()
                    with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                        with transaction(writer):
                            writer.execute("INSERT INTO sample VALUES ('pending')")
                    self.assertFalse(writer.in_transaction)
                    self.assertEqual(
                        writer.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 0
                    )
                    reader.execute("ROLLBACK")
                    with transaction(writer):
                        writer.execute("INSERT INTO sample VALUES ('retry')")
                    self.assertEqual(
                        writer.execute("SELECT value FROM sample").fetchone()[0],
                        "retry",
                    )

    def test_owned_transactions_roll_back_deferred_fk_commit_failure(self) -> None:
        for transaction in (immediate_transaction, consistent_read_transaction):
            with self.subTest(transaction=transaction.__name__):
                path = Path(self.temporary.name) / f"{transaction.__name__}-fk.db"
                with closing(connect_database(path)) as connection:
                    connection.execute(
                        "CREATE TABLE parent(id INTEGER PRIMARY KEY) STRICT"
                    )
                    connection.execute(
                        "CREATE TABLE child("
                        "parent_id INTEGER REFERENCES parent(id) "
                        "DEFERRABLE INITIALLY DEFERRED) STRICT"
                    )
                    with self.assertRaises(sqlite3.IntegrityError):
                        with transaction(connection):
                            connection.execute("INSERT INTO child VALUES (1)")
                    self.assertFalse(connection.in_transaction)
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM child").fetchone()[0],
                        0,
                    )
                    with transaction(connection):
                        connection.execute("INSERT INTO parent VALUES (2)")
                        connection.execute("INSERT INTO child VALUES (2)")
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM child").fetchone()[0],
                        1,
                    )

    def test_sqlite_auto_rollback_preserves_the_original_error(self) -> None:
        for transaction in (immediate_transaction, consistent_read_transaction):
            with self.subTest(transaction=transaction.__name__):
                path = Path(self.temporary.name) / f"{transaction.__name__}-auto.db"
                with closing(connect_database(path)) as connection:
                    connection.execute(
                        "CREATE TABLE sample(value INTEGER PRIMARY KEY) STRICT"
                    )
                    with self.assertRaises(sqlite3.IntegrityError):
                        with transaction(connection):
                            connection.execute("INSERT INTO sample VALUES (1)")
                            connection.execute(
                                "INSERT OR ROLLBACK INTO sample VALUES (1)"
                            )
                    self.assertFalse(connection.in_transaction)
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
                        0,
                    )

    def test_nested_rejection_does_not_rollback_the_callers_transaction(self) -> None:
        for transaction in (immediate_transaction, consistent_read_transaction):
            with self.subTest(transaction=transaction.__name__):
                path = Path(self.temporary.name) / f"{transaction.__name__}-owner.db"
                with closing(connect_database(path)) as connection:
                    connection.execute("CREATE TABLE sample(value TEXT) STRICT")
                    connection.execute("BEGIN")
                    connection.execute("INSERT INTO sample VALUES ('caller-owned')")
                    with self.assertRaisesRegex(
                        SQLiteConfigurationError, "nested transaction"
                    ):
                        with transaction(connection):
                            pass
                    self.assertTrue(connection.in_transaction)
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
                        1,
                    )
                    connection.execute("ROLLBACK")
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
                        0,
                    )

    def test_semantic_replay_can_hold_one_explicit_read_snapshot(self) -> None:
        with closing(connect_database(self.path)) as connection:
            connection.execute("CREATE TABLE sample(value TEXT) STRICT")
            connection.execute("INSERT INTO sample VALUES ('stable')")
            with consistent_read_transaction(connection):
                self.assertTrue(connection.in_transaction)
                self.assertEqual(
                    connection.execute("SELECT value FROM sample").fetchone()[0],
                    "stable",
                )
            self.assertFalse(connection.in_transaction)

    def test_wal_gate_matches_official_fixed_release_lines(self) -> None:
        rejected = ((3, 43, 99), (3, 44, 5), (3, 49, 1), (3, 50, 6), (3, 51, 2))
        accepted = ((3, 44, 6), (3, 50, 7), (3, 51, 3), (3, 53, 2), (4, 0, 0))
        for version in rejected:
            with self.subTest(version=version):
                self.assertFalse(wal_reset_fix_present(version))
        for version in accepted:
            with self.subTest(version=version):
                self.assertTrue(wal_reset_fix_present(version))

    def test_linked_3491_runtime_is_explicitly_rejected_for_wal(self) -> None:
        with patch("paramguard.db.sqlite3.sqlite_version_info", (3, 49, 1)):
            with self.assertRaisesRegex(SQLiteCapabilityError, "WAL-reset"):
                connect_database(self.path, journal_mode="WAL")

    def test_wal_requires_explicit_opt_in_even_on_fixed_runtime(self) -> None:
        if not wal_reset_fix_present(sqlite3.sqlite_version_info):
            self.skipTest("linked SQLite runtime does not contain WAL-reset fix")
        with closing(connect_database(self.path)) as default_connection:
            self.assertEqual(
                default_connection.execute("PRAGMA journal_mode").fetchone()[0],
                "delete",
            )
        with closing(connect_database(self.path, journal_mode="WAL")) as wal_connection:
            self.assertEqual(
                wal_connection.execute("PRAGMA journal_mode").fetchone()[0],
                "wal",
            )

    def test_capability_and_configuration_fail_closed(self) -> None:
        with self.assertRaises(SQLiteCapabilityError):
            require_sqlite_capabilities((3, 36, 0))
        with self.assertRaises(SQLiteConfigurationError):
            connect_database(self.path, journal_mode="MEMORY")
        with self.assertRaises(SQLiteConfigurationError):
            connect_database(":memory:")
        with self.assertRaises(ValueError):
            connect_database(self.path, busy_timeout_ms=True)  # type: ignore[arg-type]

    def test_migrated_database_reports_strict_integrity(self) -> None:
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(migrate_database(connection), 2)
            health = verify_database_integrity(connection)
            self.assertEqual(health.user_version, 2)
            self.assertEqual(health.journal_mode, "DELETE")

    def test_integrity_owns_one_read_snapshot_when_called_standalone(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            observed: list[tuple[str, bool]] = []
            connection.set_trace_callback(
                lambda sql: observed.append((sql, connection.in_transaction))
            )
            self.assertEqual(verify_database_integrity(connection).user_version, 2)
            self.assertFalse(connection.in_transaction)
            self.assertEqual(observed[0][0], "BEGIN")
            self.assertEqual(observed[-1][0], "COMMIT")
            reads = [
                active
                for sql, active in observed
                if sql.startswith(("SELECT", "PRAGMA"))
            ]
            self.assertTrue(reads)
            self.assertTrue(all(reads))

    def test_integrity_joins_caller_snapshot_without_committing_or_setting_pragmas(
        self,
    ) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            statements: list[str] = []
            connection.set_trace_callback(statements.append)
            before_changes = connection.total_changes
            with consistent_read_transaction(connection):
                self.assertEqual(verify_database_integrity(connection).user_version, 2)
                self.assertTrue(connection.in_transaction)
                self.assertNotIn("COMMIT", statements)
                self.assertEqual(connection.total_changes, before_changes)
            self.assertEqual(statements.count("BEGIN"), 1)
            self.assertEqual(statements.count("COMMIT"), 1)
            self.assertFalse(
                any(sql.startswith("PRAGMA ") and "=" in sql for sql in statements)
            )

    def test_integrity_rejects_unsafe_pragmas_without_repairing_them(self) -> None:
        for pragma, unsafe in (
            ("foreign_keys", 0),
            ("trusted_schema", 1),
            ("recursive_triggers", 0),
            ("synchronous", 0),
        ):
            with self.subTest(pragma=pragma):
                path = Path(self.temporary.name) / f"unsafe-{pragma}.db"
                with closing(connect_database(path)) as connection:
                    migrate_database(connection)
                    connection.execute(f"PRAGMA {pragma}={unsafe}")
                    with self.assertRaises(SQLiteConfigurationError):
                        verify_database_integrity(connection)
                    self.assertFalse(connection.in_transaction)
                    self.assertEqual(
                        connection.execute(f"PRAGMA {pragma}").fetchone()[0], unsafe
                    )

    def test_second_migration_upgrades_an_existing_v1_database(self) -> None:
        migrations = load_packaged_migrations()
        self.assertEqual(len(migrations), 2)
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                migrate_database(connection, migrations=migrations[:1]),
                1,
            )
            self.assertEqual(migrate_database(connection), 2)
            health = verify_database_integrity(connection)
            self.assertEqual(health.user_version, 2)

            unique_index_columns = tuple(
                tuple(
                    str(column[2])
                    for column in connection.execute(
                        f"PRAGMA index_info('{str(index[1])}')"
                    )
                )
                for index in connection.execute("PRAGMA index_list('r1_locks')")
                if int(index[2]) == 1
            )
            self.assertNotIn(("task_revision",), unique_index_columns)

    def test_integrity_rejects_temp_objects_without_removing_them(self) -> None:
        attacks = (
            "CREATE TEMP TABLE scratch(value TEXT) STRICT",
            "CREATE TEMP VIEW scratch AS SELECT task_id FROM main.tasks",
            "CREATE TEMP TRIGGER scratch BEFORE INSERT ON main.tasks "
            "BEGIN SELECT RAISE(IGNORE); END",
        )
        for index, statement in enumerate(attacks):
            for caller_owned in (False, True):
                with self.subTest(attack=index, caller_owned=caller_owned):
                    path = Path(self.temporary.name) / f"temp-{index}-{caller_owned}.db"
                    with closing(connect_database(path)) as connection:
                        migrate_database(connection)
                        connection.execute(statement)
                        before = tuple(
                            connection.execute("SELECT * FROM temp.sqlite_schema")
                        )
                        if caller_owned:
                            connection.execute("BEGIN")
                        before_changes = connection.total_changes
                        with self.assertRaisesRegex(SQLiteConfigurationError, "schema"):
                            verify_database_integrity(connection)
                        self.assertEqual(connection.in_transaction, caller_owned)
                        self.assertEqual(connection.total_changes, before_changes)
                        self.assertEqual(
                            tuple(
                                connection.execute("SELECT * FROM temp.sqlite_schema")
                            ),
                            before,
                        )
                        if caller_owned:
                            connection.execute("ROLLBACK")

    def test_integrity_rejects_attached_database_without_detaching_it(self) -> None:
        for caller_owned in (False, True):
            with self.subTest(caller_owned=caller_owned):
                with closing(connect_database(self.path)) as connection:
                    migrate_database(connection)
                    connection.execute("ATTACH DATABASE ':memory:' AS unapproved")
                    connection.execute(
                        "CREATE TABLE unapproved.sentinel(value TEXT) STRICT"
                    )
                    connection.execute(
                        "INSERT INTO unapproved.sentinel VALUES ('synthetic')"
                    )
                    before = tuple(connection.execute("PRAGMA database_list"))
                    if caller_owned:
                        connection.execute("BEGIN")
                    before_changes = connection.total_changes
                    with self.assertRaisesRegex(SQLiteConfigurationError, "schema"):
                        verify_database_integrity(connection)
                    self.assertEqual(connection.in_transaction, caller_owned)
                    self.assertEqual(connection.total_changes, before_changes)
                    self.assertEqual(
                        tuple(connection.execute("PRAGMA database_list")), before
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT value FROM unapproved.sentinel"
                        ).fetchone()[0],
                        "synthetic",
                    )
                    if caller_owned:
                        connection.execute("ROLLBACK")

    def test_migration_rejects_external_schema_scope_before_writes(self) -> None:
        for name, statement in (
            ("temp", "CREATE TEMP TABLE scratch(value TEXT) STRICT"),
            ("attached", "ATTACH DATABASE ':memory:' AS unapproved"),
        ):
            with self.subTest(schema=name):
                path = Path(self.temporary.name) / f"migration-{name}.db"
                with closing(connect_database(path)) as connection:
                    connection.execute(statement)
                    before = tuple(connection.execute("PRAGMA database_list"))
                    with self.assertRaisesRegex(SQLiteConfigurationError, "schema"):
                        migrate_database(connection)
                    self.assertFalse(connection.in_transaction)
                    self.assertEqual(connection.total_changes, 0)
                    self.assertEqual(
                        tuple(connection.execute("PRAGMA database_list")), before
                    )
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0], 0
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM main.sqlite_schema"
                        ).fetchone()[0],
                        0,
                    )

    def test_integrity_rejects_unapproved_view_without_deleting_it(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute(
                "CREATE VIEW unapproved_view AS SELECT task_id FROM main.tasks"
            )
            with self.assertRaisesRegex(
                DatabaseIntegrityError, "view definition drift"
            ):
                verify_database_integrity(connection)
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM main.sqlite_schema WHERE name='unapproved_view'"
                ).fetchone()
            )

    def test_integrity_accepts_an_empty_initialized_temp_schema(self) -> None:
        with closing(connect_database(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM temp.sqlite_schema"
                ).fetchone()[0],
                0,
            )
            self.assertIn(
                "temp", [row[1] for row in connection.execute("PRAGMA database_list")]
            )
            self.assertEqual(migrate_database(connection), 2)
            self.assertEqual(verify_database_integrity(connection).user_version, 2)

    def test_integrity_rejects_unapproved_global_revision_unique_index(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute(
                "CREATE UNIQUE INDEX unapproved_revision_unique "
                "ON r1_locks(task_revision)"
            )
            with self.assertRaisesRegex(
                DatabaseIntegrityError, "index definition drift"
            ):
                verify_database_integrity(connection)
            # Verification must never silently repair or delete DB objects.
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_schema WHERE name=?",
                    ("unapproved_revision_unique",),
                ).fetchone()
            )

    def test_integrity_rejects_missing_required_index(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute("DROP INDEX r1_decisions_latest_idx")
            with self.assertRaisesRegex(
                DatabaseIntegrityError, "index definition drift"
            ):
                verify_database_integrity(connection)

    def test_integrity_rejects_same_name_changed_index_definition(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute("DROP INDEX r1_decisions_latest_idx")
            connection.execute(
                "CREATE INDEX r1_decisions_latest_idx ON r1_decisions(command_id)"
            )
            with self.assertRaisesRegex(
                DatabaseIntegrityError, "index definition drift"
            ):
                verify_database_integrity(connection)

    def test_integrity_rejects_unapproved_columns_including_generated(self) -> None:
        declarations = (
            "unapproved_note TEXT",
            "unapproved_flag INTEGER DEFAULT 1 CHECK(unapproved_flag=1)",
            "unapproved_derived INTEGER GENERATED ALWAYS AS (revision + 1) VIRTUAL",
        )
        for index, declaration in enumerate(declarations):
            with self.subTest(declaration=declaration):
                path = Path(self.temporary.name) / f"extra-column-{index}.db"
                with closing(connect_database(path)) as connection:
                    migrate_database(connection)
                    connection.execute(f"ALTER TABLE tasks ADD COLUMN {declaration}")
                    observed_sql = connection.execute(
                        "SELECT sql FROM main.sqlite_schema WHERE name='tasks'"
                    ).fetchone()[0]
                    with self.assertRaisesRegex(
                        DatabaseIntegrityError, "table definition drift"
                    ):
                        verify_database_integrity(connection)
                    self.assertEqual(
                        connection.execute(
                            "SELECT sql FROM main.sqlite_schema WHERE name='tasks'"
                        ).fetchone()[0],
                        observed_sql,
                    )

    def test_integrity_rejects_unapproved_table_without_deleting_it(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute("CREATE TABLE unapproved_table(note TEXT) STRICT")
            with self.assertRaisesRegex(
                DatabaseIntegrityError, "table definition drift"
            ):
                verify_database_integrity(connection)
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM main.sqlite_schema WHERE name='unapproved_table'"
                ).fetchone()
            )

    def test_integrity_rejects_changed_check_default_type_nullability_and_fk(
        self,
    ) -> None:
        revision = "revision INTEGER NOT NULL CHECK(revision >= 0)"
        attacks = (
            ("missing-check", "tasks", revision, "revision INTEGER NOT NULL"),
            (
                "weakened-check",
                "tasks",
                revision,
                "revision INTEGER NOT NULL CHECK(revision >= -9)",
            ),
            (
                "changed-default",
                "tasks",
                revision,
                "revision INTEGER NOT NULL DEFAULT 9 CHECK(revision >= 0)",
            ),
            (
                "changed-type",
                "tasks",
                revision,
                "revision TEXT NOT NULL CHECK(revision >= 0)",
            ),
            (
                "nullable-column",
                "tasks",
                revision,
                "revision INTEGER CHECK(revision >= 0)",
            ),
            ("missing-fk", "task_assignments", " REFERENCES tasks(task_id)", ""),
        )
        for name, table, original_fragment, replacement in attacks:
            with self.subTest(attack=name):
                path = Path(self.temporary.name) / f"forged-{name}.db"
                with closing(connect_database(path)) as connection:
                    migrate_database(connection)
                    original = connection.execute(
                        "SELECT sql FROM main.sqlite_schema WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()[0]
                    forged = original.replace(original_fragment, replacement)
                    self.assertNotEqual(forged, original)
                    # Adversarial fixture only: rewrite this temporary database,
                    # close it, then reopen so SQLite parses the changed DDL.
                    connection.execute("PRAGMA writable_schema=ON")
                    try:
                        connection.execute(
                            "UPDATE main.sqlite_schema SET sql=? WHERE type='table' AND name=?",
                            (forged, table),
                        )
                    finally:
                        connection.execute("PRAGMA writable_schema=OFF")
                with closing(connect_database(path)) as connection:
                    with self.assertRaisesRegex(
                        DatabaseIntegrityError, "table definition drift"
                    ):
                        verify_database_integrity(connection)

    def test_integrity_accepts_analyze_and_vacuum_without_schema_drift(self) -> None:
        with closing(connect_database(self.path)) as connection:
            migrate_database(connection)
            connection.execute("ANALYZE")
            connection.execute("VACUUM")
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM main.sqlite_schema WHERE name='sqlite_stat1'"
                ).fetchone()
            )
            self.assertEqual(verify_database_integrity(connection).user_version, 2)


if __name__ == "__main__":
    unittest.main()
