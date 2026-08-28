"""SQLite connection and migration controls for the learning persistence PoC.

Every connection uses SQLite's native autocommit mode
(``isolation_level=None``) and repository code opens transactions explicitly
with ``BEGIN IMMEDIATE``.  That single rule behaves the same on Python 3.11
and 3.13 and prevents ``executescript()`` from silently deciding transaction
boundaries for us.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
from importlib import resources
from pathlib import Path
import re
import sqlite3


MINIMUM_SQLITE_VERSION = (3, 37, 0)
DEFAULT_BUSY_TIMEOUT_MS = 5_000
DEFAULT_JOURNAL_MODE = "DELETE"
SUPPORTED_JOURNAL_MODES = frozenset({"DELETE", "WAL"})

_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_[a-z0-9_]+\.sql$")
_FORBIDDEN_MIGRATION_PREFIXES = frozenset(
    {
        "ATTACH",
        "BEGIN",
        "COMMIT",
        "DETACH",
        "END",
        "PRAGMA",
        "RELEASE",
        "ROLLBACK",
        "SAVEPOINT",
        "VACUUM",
    }
)


class DatabaseError(RuntimeError):
    """Base class for persistence-infrastructure failures."""


class SQLiteCapabilityError(DatabaseError):
    """The linked SQLite runtime cannot meet the schema contract."""


class SQLiteConfigurationError(DatabaseError):
    """A requested or observed connection setting is unsafe."""


class MigrationError(DatabaseError):
    """Migration resources and database metadata disagree."""


class DatabaseIntegrityError(DatabaseError):
    """SQLite integrity or foreign-key verification failed."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str
    sha256: str

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version <= 0:
            raise ValueError("migration version must be a positive integer")
        match = _MIGRATION_NAME.fullmatch(self.name)
        if match is None or int(match.group("version")) != self.version:
            raise ValueError("migration name must encode its four-digit version")
        if type(self.sql) is not str or self.sql.strip() == "":
            raise ValueError("migration SQL must be non-empty text")
        expected = hashlib.sha256(self.sql.encode("utf-8")).hexdigest()
        if type(self.sha256) is not str or self.sha256 != expected:
            raise ValueError("migration sha256 does not match its UTF-8 SQL")


@dataclass(frozen=True, slots=True)
class DatabaseHealth:
    sqlite_version: str
    journal_mode: str
    synchronous: int
    foreign_keys: int
    busy_timeout_ms: int
    trusted_schema: int
    user_version: int


def wal_reset_fix_present(version: tuple[int, int, int]) -> bool:
    """Return whether an official SQLite WAL-reset fix release is represented.

    SQLite documents the main-line fix in 3.51.3 and later and backports in
    3.44.6 and 3.50.7.  Versions between those maintained branches are not
    inferred to contain the fix merely because their number is greater than a
    backport number.
    """

    if (
        type(version) is not tuple
        or len(version) != 3
        or any(type(item) is not int or item < 0 for item in version)
    ):
        raise TypeError("version must be an exact three-integer tuple")
    major, minor, patch = version
    if major > 3:
        return True
    if major < 3:
        return False
    if minor > 51:
        return True
    if minor == 51:
        return patch >= 3
    if minor == 50:
        return patch >= 7
    if minor == 44:
        return patch >= 6
    return False


def require_sqlite_capabilities(
    version: tuple[int, int, int] | None = None,
) -> tuple[int, int, int]:
    checked = sqlite3.sqlite_version_info if version is None else version
    if (
        type(checked) is not tuple
        or len(checked) != 3
        or any(type(item) is not int or item < 0 for item in checked)
    ):
        raise TypeError("SQLite version must be an exact three-integer tuple")
    if checked < MINIMUM_SQLITE_VERSION:
        raise SQLiteCapabilityError(
            "SQLite 3.37.0 or newer is required for STRICT tables; linked "
            f"runtime is {'.'.join(map(str, checked))}"
        )
    return checked


def _require_exact_int(name: str, value: int, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _pragma_scalar(connection: sqlite3.Connection, pragma: str) -> object:
    row = connection.execute(f"PRAGMA {pragma}").fetchone()
    if row is None or len(row) != 1:
        raise SQLiteConfigurationError(f"PRAGMA {pragma} returned no scalar value")
    return row[0]


def _set_and_verify_pragmas(
    connection: sqlite3.Connection,
    *,
    journal_mode: str,
    busy_timeout_ms: int,
    runtime_version: tuple[int, int, int],
) -> DatabaseHealth:
    if type(journal_mode) is not str:
        raise TypeError("journal_mode must be an exact str value")
    checked_mode = journal_mode.upper()
    if checked_mode not in SUPPORTED_JOURNAL_MODES:
        raise SQLiteConfigurationError("journal_mode must be DELETE or WAL")
    if checked_mode == "WAL" and not wal_reset_fix_present(runtime_version):
        raise SQLiteCapabilityError(
            "WAL is opt-in only on an SQLite release containing the official "
            "WAL-reset fix; this runtime must use DELETE rollback journal mode"
        )
    timeout = _require_exact_int(
        "busy_timeout_ms", busy_timeout_ms, minimum=1, maximum=60_000
    )

    # Set each safety property separately, then read every property back.  Do
    # not assume that a PRAGMA request was accepted by the linked runtime/VFS.
    connection.execute(f"PRAGMA busy_timeout={timeout}")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA recursive_triggers=ON")
    journal_row = connection.execute(f"PRAGMA journal_mode={checked_mode}").fetchone()
    if journal_row is None or str(journal_row[0]).upper() != checked_mode:
        observed = None if journal_row is None else journal_row[0]
        raise SQLiteConfigurationError(
            f"journal_mode requested {checked_mode}, observed {observed}"
        )
    connection.execute("PRAGMA synchronous=EXTRA")

    health = _read_and_verify_pragmas(connection, runtime_version=runtime_version)
    if health.busy_timeout_ms != timeout:
        raise SQLiteConfigurationError(
            f"busy_timeout requested {timeout}, observed {health.busy_timeout_ms}"
        )
    if health.journal_mode != checked_mode:
        raise SQLiteConfigurationError(f"journal_mode drifted to {health.journal_mode}")
    return health


def _read_and_verify_pragmas(
    connection: sqlite3.Connection, *, runtime_version: tuple[int, int, int]
) -> DatabaseHealth:
    """Check existing safety settings without changing a caller's transaction."""

    observed_timeout = int(_pragma_scalar(connection, "busy_timeout"))
    observed_fk = int(_pragma_scalar(connection, "foreign_keys"))
    observed_trusted = int(_pragma_scalar(connection, "trusted_schema"))
    observed_recursive = int(_pragma_scalar(connection, "recursive_triggers"))
    observed_journal = str(_pragma_scalar(connection, "journal_mode")).upper()
    observed_sync = int(_pragma_scalar(connection, "synchronous"))
    if not 1 <= observed_timeout <= 60_000:
        raise SQLiteConfigurationError(
            f"busy_timeout must be from 1 to 60000, observed {observed_timeout}"
        )
    if observed_fk != 1:
        raise SQLiteConfigurationError("foreign_keys must be enabled")
    if observed_trusted != 0:
        raise SQLiteConfigurationError("trusted_schema must be disabled")
    if observed_recursive != 1:
        raise SQLiteConfigurationError("recursive_triggers must be enabled")
    if observed_journal not in SUPPORTED_JOURNAL_MODES:
        raise SQLiteConfigurationError(f"journal_mode drifted to {observed_journal}")
    if observed_journal == "WAL" and not wal_reset_fix_present(runtime_version):
        raise SQLiteCapabilityError(
            "WAL requires an SQLite release containing the official WAL-reset fix"
        )
    if observed_sync != 3:
        raise SQLiteConfigurationError(
            f"synchronous requested EXTRA(3), observed {observed_sync}"
        )
    return DatabaseHealth(
        sqlite_version=".".join(map(str, runtime_version)),
        journal_mode=observed_journal,
        synchronous=observed_sync,
        foreign_keys=observed_fk,
        busy_timeout_ms=observed_timeout,
        trusted_schema=observed_trusted,
        user_version=int(_pragma_scalar(connection, "user_version")),
    )


def connect_database(
    database_path: str | Path,
    *,
    journal_mode: str = DEFAULT_JOURNAL_MODE,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> sqlite3.Connection:
    """Open and fully verify one SQLite connection.

    The explicit ``isolation_level=None`` is deliberate on both supported
    Python lines.  Repository methods issue ``BEGIN IMMEDIATE`` themselves.
    """

    if type(database_path) is str:
        path_text = database_path
    elif isinstance(database_path, Path):
        path_text = str(database_path)
    else:
        raise TypeError("database_path must be an exact str or pathlib.Path")
    if path_text == "" or path_text == ":memory:":
        raise SQLiteConfigurationError(
            "Persistence PoC requires a non-empty on-disk database path"
        )
    timeout = _require_exact_int(
        "busy_timeout_ms", busy_timeout_ms, minimum=1, maximum=60_000
    )
    runtime_version = require_sqlite_capabilities()
    connection = sqlite3.connect(
        path_text,
        timeout=timeout / 1000,
        isolation_level=None,
        check_same_thread=True,
        uri=False,
    )
    connection.row_factory = sqlite3.Row
    try:
        _set_and_verify_pragmas(
            connection,
            journal_mode=journal_mode,
            busy_timeout_ms=timeout,
            runtime_version=runtime_version,
        )
    except BaseException:
        connection.close()
        raise
    return connection


def _commit_owned_transaction(
    connection: sqlite3.Connection, *, ended_early_message: str
) -> None:
    """Commit an owned transaction or restore autocommit before propagating."""

    if not connection.in_transaction:
        raise SQLiteConfigurationError(ended_early_message)
    try:
        connection.execute("COMMIT")
    except BaseException:
        # SQLite documents that a failed COMMIT can leave the transaction
        # active.  Never return a reusable connection with pending writes.
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


@contextmanager
def immediate_transaction(connection: sqlite3.Connection) -> Iterator[None]:
    """Open exactly one explicit write transaction and safely unwind it."""

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be sqlite3.Connection")
    if connection.isolation_level is not None:
        raise SQLiteConfigurationError(
            "connection must use isolation_level=None for explicit transactions"
        )
    if connection.in_transaction:
        raise SQLiteConfigurationError("nested transaction is not allowed")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        _commit_owned_transaction(
            connection,
            ended_early_message=(
                "transaction ended before the repository commit boundary"
            ),
        )


@contextmanager
def consistent_read_transaction(connection: sqlite3.Connection) -> Iterator[None]:
    """Hold one SQLite snapshot while replaying cross-table invariants."""

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be sqlite3.Connection")
    if connection.isolation_level is not None:
        raise SQLiteConfigurationError(
            "connection must use isolation_level=None for explicit transactions"
        )
    if connection.in_transaction:
        raise SQLiteConfigurationError("nested transaction is not allowed")
    connection.execute("BEGIN")
    try:
        yield
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        _commit_owned_transaction(
            connection,
            ended_early_message=(
                "read transaction ended before semantic replay completed"
            ),
        )


def _split_sql_statements(sql: str) -> tuple[str, ...]:
    """Split controlled migration SQL without using ``executescript``."""

    if type(sql) is not str:
        raise TypeError("sql must be an exact str value")
    statements: list[str] = []
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            buffer = ""
            if statement:
                statements.append(statement)
    if buffer.strip():
        raise MigrationError("migration contains an incomplete SQL statement")
    if not statements:
        raise MigrationError("migration contains no SQL statements")
    for statement in statements:
        without_comments = re.sub(r"(?m)^\s*--.*$", "", statement).lstrip()
        first = without_comments.split(None, 1)[0].upper() if without_comments else ""
        if first in _FORBIDDEN_MIGRATION_PREFIXES:
            raise MigrationError(
                f"migration transaction/control statement is forbidden: {first}"
            )
    return tuple(statements)


def load_packaged_migrations() -> tuple[Migration, ...]:
    root = resources.files("paramguard").joinpath("migrations")
    candidates = sorted(
        item for item in root.iterdir() if item.is_file() and item.name.endswith(".sql")
    )
    migrations: list[Migration] = []
    for item in candidates:
        match = _MIGRATION_NAME.fullmatch(item.name)
        if match is None:
            raise MigrationError(f"invalid packaged migration filename: {item.name}")
        raw = item.read_bytes()
        try:
            sql = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise MigrationError(f"migration is not UTF-8: {item.name}") from error
        migrations.append(
            Migration(
                version=int(match.group("version")),
                name=item.name,
                sql=sql,
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    if not migrations:
        raise MigrationError("no packaged migrations were found")
    versions = tuple(item.version for item in migrations)
    if versions != tuple(range(1, len(migrations) + 1)):
        raise MigrationError("migration versions must be contiguous starting at 1")
    return tuple(migrations)


def _verify_connection_schema_scope(connection: sqlite3.Connection) -> None:
    """Reject caller-added schemas before trusting main-schema checks.

    TEMP objects can shadow reads or trigger writes even when main DDL is
    unchanged. This is a connection contract, not a sandbox for arbitrary SQL.
    An initialized but empty TEMP schema is harmless and remains allowed.
    """

    schemas = {row[1] for row in connection.execute("PRAGMA database_list")}
    if "main" not in schemas or schemas - {"main", "temp"}:
        raise SQLiteConfigurationError("connection has an unapproved schema")
    if connection.execute("SELECT 1 FROM temp.sqlite_schema LIMIT 1").fetchone():
        raise SQLiteConfigurationError(
            "connection has an unapproved temp schema object"
        )


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name=?", (table_name,)
    ).fetchone()
    return row is not None


def _migration_rows(connection: sqlite3.Connection) -> tuple[sqlite3.Row, ...]:
    if not _table_exists(connection, "_paramguard_migrations"):
        return ()
    return tuple(
        connection.execute(
            "SELECT version, name, sha256 FROM main._paramguard_migrations "
            "ORDER BY version"
        ).fetchall()
    )


def _verify_migration_state(
    connection: sqlite3.Connection,
    migrations: Sequence[Migration],
    *,
    allow_missing: bool,
) -> int:
    user_version = int(_pragma_scalar(connection, "user_version"))
    table_exists = _table_exists(connection, "_paramguard_migrations")
    rows = _migration_rows(connection)
    if not table_exists:
        if user_version != 0:
            raise MigrationError(
                "user_version is non-zero but migration ledger is missing"
            )
        if allow_missing:
            return 0
        raise MigrationError("migration ledger is missing")
    if len(rows) > len(migrations):
        raise MigrationError("database contains unknown future migrations")
    expected_versions = tuple(range(1, len(rows) + 1))
    actual_versions = tuple(int(row["version"]) for row in rows)
    if actual_versions != expected_versions:
        raise MigrationError("applied migration versions are not contiguous")
    for row, expected in zip(rows, migrations[: len(rows)], strict=True):
        if row["name"] != expected.name or row["sha256"] != expected.sha256:
            raise MigrationError(
                f"migration checksum/name drift at version {expected.version}"
            )
    if user_version != len(rows):
        raise MigrationError(
            f"PRAGMA user_version={user_version} disagrees with migration ledger={len(rows)}"
        )
    return len(rows)


def migrate_database(
    connection: sqlite3.Connection,
    *,
    migrations: Sequence[Migration] | None = None,
) -> int:
    """Apply verified migrations atomically, one statement at a time."""

    selected = load_packaged_migrations() if migrations is None else tuple(migrations)
    if not selected or any(not isinstance(item, Migration) for item in selected):
        raise TypeError("migrations must be a non-empty sequence of Migration values")
    versions = tuple(item.version for item in selected)
    if versions != tuple(range(1, len(selected) + 1)):
        raise MigrationError("migration versions must be contiguous starting at 1")

    with immediate_transaction(connection):
        _verify_connection_schema_scope(connection)
        applied = _verify_migration_state(connection, selected, allow_missing=True)
        for migration in selected[applied:]:
            for statement in _split_sql_statements(migration.sql):
                connection.execute(statement)
            if not _table_exists(connection, "_paramguard_migrations"):
                raise MigrationError(
                    "first migration did not create _paramguard_migrations"
                )
            connection.execute(
                "INSERT INTO main._paramguard_migrations"
                "(version, name, sha256, applied_at) "
                "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                (migration.version, migration.name, migration.sha256),
            )
            connection.execute(f"PRAGMA user_version={migration.version}")
        final_version = _verify_migration_state(
            connection, selected, allow_missing=False
        )
    return final_version


def _view_definitions(connection: sqlite3.Connection) -> dict[str, tuple]:
    return {
        name: (table, sql)
        for name, table, sql in connection.execute(
            "SELECT name, tbl_name, sql FROM main.sqlite_schema WHERE type='view'"
        )
    }


def _table_definitions(connection: sqlite3.Connection) -> dict[str, tuple]:
    """Capture approved main-schema DDL and its parsed column/table metadata.

    DDL includes CHECK/FK/default/generated expressions that column names alone
    cannot attest. Ignore physical root pages and SQLite's ANALYZE statistics;
    neither is application schema identity. Do not normalize arbitrary SQL.
    """

    definitions = {}
    for name, sql in connection.execute(
        "SELECT name, sql FROM main.sqlite_schema WHERE type='table' "
        "AND name NOT IN ('sqlite_stat1', 'sqlite_stat4')"
    ):
        columns = tuple(
            tuple(row)
            for row in connection.execute(
                'SELECT cid, name, type, "notnull", dflt_value, pk, hidden '
                "FROM pragma_table_xinfo(?, 'main') ORDER BY cid",
                (name,),
            )
        )
        attributes = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT type, ncol, wr, strict FROM pragma_table_list() "
                "WHERE schema='main' AND name=?",
                (name,),
            )
        )
        definitions[name] = (sql, columns, attributes)
    return definitions


def _index_definitions(connection: sqlite3.Connection) -> dict[str, tuple]:
    """Capture declared and implicit indexes without trusting their names.

    Root pages are physical storage details, not schema identity.  SQL alone
    is insufficient for UNIQUE/PRIMARY KEY autoindexes because their SQL is
    NULL, so include the runtime's key, collation and uniqueness metadata.
    Table-valued PRAGMAs bind names as values, including unusual index names.
    """

    definitions = {}
    for row in connection.execute(
        "SELECT name, tbl_name, sql FROM main.sqlite_schema WHERE type='index'"
    ):
        name, table, sql = row
        attributes = tuple(
            tuple(item)
            for item in connection.execute(
                'SELECT "unique", origin, partial '
                "FROM pragma_index_list(?, 'main') WHERE name=?",
                (table, name),
            )
        )
        columns = tuple(
            tuple(item)
            for item in connection.execute(
                "SELECT * FROM pragma_index_xinfo(?, 'main') ORDER BY seqno",
                (name,),
            )
        )
        definitions[name] = (table, sql, attributes, columns)
    return definitions


def verify_database_integrity(connection: sqlite3.Connection) -> DatabaseHealth:
    """Verify structure and safety settings in one caller-owned or local snapshot.

    A caller may keep this transaction open for subsequent semantic replay.
    Verification never repairs PRAGMAs or commits the caller's transaction.
    """

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be sqlite3.Connection")
    if connection.isolation_level is not None:
        raise SQLiteConfigurationError(
            "connection must use isolation_level=None for explicit transactions"
        )
    if connection.in_transaction:
        return _verify_database_integrity_snapshot(connection)
    with consistent_read_transaction(connection):
        return _verify_database_integrity_snapshot(connection)


def _verify_database_integrity_snapshot(
    connection: sqlite3.Connection,
) -> DatabaseHealth:
    """Read approved schema, data checks and migrations in one snapshot."""

    _verify_connection_schema_scope(connection)
    migrations = load_packaged_migrations()
    _verify_migration_state(connection, migrations, allow_missing=False)
    integrity = tuple(row[0] for row in connection.execute("PRAGMA integrity_check"))
    if integrity != ("ok",):
        raise DatabaseIntegrityError(
            "PRAGMA integrity_check failed: " + "; ".join(map(str, integrity))
        )
    foreign_key_rows = tuple(connection.execute("PRAGMA foreign_key_check"))
    if foreign_key_rows:
        raise DatabaseIntegrityError(
            f"PRAGMA foreign_key_check returned {len(foreign_key_rows)} row(s)"
        )
    required_strict = {
        "_paramguard_migrations",
        "tasks",
        "task_parameters",
        "evidence_artifacts",
        "task_assignments",
        "r1_decisions",
        "r1_locks",
        "command_receipts",
        "audit_outbox",
    }
    table_list = {
        str(row[1]): int(row[5])
        for row in connection.execute("PRAGMA table_list")
        if row[0] == "main"
    }
    non_strict = sorted(name for name in required_strict if table_list.get(name) != 1)
    if non_strict:
        raise DatabaseIntegrityError(
            "required table missing or not STRICT: " + ", ".join(non_strict)
        )

    # Let the same SQLite runtime normalize final DDL, including tables and
    # triggers replaced by later migrations. Object names do not attest behavior.
    # This isolated reference database contains no user evidence or records.
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as reference:
        reference.row_factory = sqlite3.Row
        migrate_database(reference, migrations=migrations)
        expected_triggers = {
            str(row[0]): (str(row[1]), str(row[2]))
            for row in reference.execute(
                "SELECT name, tbl_name, sql FROM main.sqlite_schema WHERE type='trigger'"
            )
        }
        expected_indexes = _index_definitions(reference)
        expected_tables = _table_definitions(reference)
        expected_views = _view_definitions(reference)
    observed_triggers = {
        str(row[0]): (str(row[1]), str(row[2]))
        for row in connection.execute(
            "SELECT name, tbl_name, sql FROM main.sqlite_schema WHERE type='trigger'"
        )
    }
    missing_triggers = sorted(expected_triggers.keys() - observed_triggers.keys())
    if missing_triggers:
        raise DatabaseIntegrityError(
            "required integrity trigger missing: " + ", ".join(missing_triggers)
        )
    if observed_triggers != expected_triggers:
        raise DatabaseIntegrityError("integrity trigger definition drift")
    if _index_definitions(connection) != expected_indexes:
        raise DatabaseIntegrityError("integrity index definition drift")
    if _table_definitions(connection) != expected_tables:
        raise DatabaseIntegrityError("integrity table definition drift")
    if _view_definitions(connection) != expected_views:
        raise DatabaseIntegrityError("integrity view definition drift")

    return _read_and_verify_pragmas(
        connection,
        runtime_version=require_sqlite_capabilities(),
    )
