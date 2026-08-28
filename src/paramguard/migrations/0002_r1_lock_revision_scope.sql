-- R1 task revisions are aggregate-local, not globally unique.
-- Rebuild the table because SQLite cannot drop the implicit UNIQUE index.
DROP TRIGGER tasks_valid_transition;
DROP TRIGGER r1_locks_no_update;
DROP TRIGGER r1_locks_validate_insert;
DROP TRIGGER r1_locks_no_delete;

CREATE TABLE r1_locks_rebuilt (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    decision_count INTEGER NOT NULL CHECK(decision_count > 0),
    snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256) = 64 AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),
    evidence_manifest_hash TEXT NOT NULL CHECK(length(evidence_manifest_hash) = 64 AND evidence_manifest_hash NOT GLOB '*[^0-9a-f]*'),
    reviewer_id TEXT NOT NULL,
    locked_at TEXT NOT NULL,
    command_id TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO r1_locks_rebuilt(
    task_id, task_revision, decision_count, snapshot_sha256,
    evidence_manifest_hash, reviewer_id, locked_at, command_id
)
SELECT
    task_id, task_revision, decision_count, snapshot_sha256,
    evidence_manifest_hash, reviewer_id, locked_at, command_id
FROM r1_locks;

DROP TABLE r1_locks;
ALTER TABLE r1_locks_rebuilt RENAME TO r1_locks;

CREATE TRIGGER tasks_valid_transition
BEFORE UPDATE ON tasks
WHEN NOT (
    OLD.state = 'HUMAN_REVIEW_OPEN'
    AND NEW.revision = OLD.revision + 1
    AND (
        (
            NEW.state = 'HUMAN_REVIEW_OPEN'
            AND NEW.r1_locked_at IS OLD.r1_locked_at
            AND EXISTS (
                SELECT 1 FROM r1_decisions d
                WHERE d.task_id = OLD.task_id
                  AND d.task_revision = NEW.revision
            )
        )
        OR
        (
            NEW.state = 'HUMAN_REVIEW_LOCKED'
            AND NEW.r1_locked_at IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM r1_locks l
                WHERE l.task_id = OLD.task_id
                  AND l.task_revision = NEW.revision
                  AND l.locked_at = NEW.r1_locked_at
            )
        )
    )
) BEGIN
    SELECT RAISE(ABORT, 'invalid task state/revision transition');
END;

CREATE TRIGGER r1_locks_no_update
BEFORE UPDATE ON r1_locks BEGIN
    SELECT RAISE(ABORT, 'R1 locks are write-once');
END;

CREATE TRIGGER r1_locks_validate_insert
BEFORE INSERT ON r1_locks
WHEN NOT EXISTS (
    SELECT 1
    FROM tasks t
    JOIN task_assignments a ON a.task_id = t.task_id AND a.phase = 'R1'
    WHERE t.task_id = NEW.task_id
      AND t.state = 'HUMAN_REVIEW_OPEN'
      AND t.evidence_manifest_hash = NEW.evidence_manifest_hash
      AND a.actor_id = NEW.reviewer_id
      AND a.actor_role = 'R1_REVIEWER'
      AND NEW.task_revision = t.revision + 1
      AND NEW.decision_count = (
          SELECT COUNT(*) FROM task_parameters p WHERE p.task_id = NEW.task_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM task_parameters p
          WHERE p.task_id = NEW.task_id
            AND NOT EXISTS (
                SELECT 1 FROM r1_decisions d
                WHERE d.task_id = p.task_id
                  AND d.parameter_id = p.parameter_id
            )
      )
) BEGIN
    SELECT RAISE(ABORT, 'R1 lock binding, completeness, or revision is invalid');
END;

CREATE TRIGGER r1_locks_no_delete
BEFORE DELETE ON r1_locks BEGIN
    SELECT RAISE(ABORT, 'R1 locks are write-once');
END;
