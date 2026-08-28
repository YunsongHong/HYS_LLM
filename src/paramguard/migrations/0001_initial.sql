-- ParamGuard SQLite learning PoC: durable registration and R1 only.
CREATE TABLE _paramguard_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    workflow_mode TEXT NOT NULL CHECK(workflow_mode = 'STRICT_SEQUENTIAL'),
    state TEXT NOT NULL CHECK(state IN ('HUMAN_REVIEW_OPEN', 'HUMAN_REVIEW_LOCKED')),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    data_classification TEXT NOT NULL CHECK(data_classification = 'SYNTHETIC'),
    evidence_manifest_id TEXT NOT NULL,
    evidence_manifest_hash TEXT NOT NULL CHECK(length(evidence_manifest_hash) = 64 AND evidence_manifest_hash NOT GLOB '*[^0-9a-f]*'),
    evidence_manifest_json TEXT NOT NULL,
    pipeline_spec_id TEXT NOT NULL,
    pipeline_spec_hash TEXT NOT NULL CHECK(length(pipeline_spec_hash) = 64 AND pipeline_spec_hash NOT GLOB '*[^0-9a-f]*'),
    pipeline_spec_json TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    r1_locked_at TEXT
) STRICT;

CREATE TABLE task_parameters (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    parameter_id TEXT NOT NULL,
    PRIMARY KEY(task_id, parameter_id),
    UNIQUE(task_id, ordinal)
) STRICT;

CREATE TABLE evidence_artifacts (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    artifact_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('LEFT_PHOTO', 'RIGHT_SCREENSHOT')),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    byte_length INTEGER NOT NULL CHECK(byte_length > 0),
    media_type TEXT NOT NULL,
    PRIMARY KEY(task_id, artifact_id),
    UNIQUE(task_id, role)
) STRICT;

CREATE TABLE task_assignments (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    phase TEXT NOT NULL CHECK(phase = 'R1'),
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL CHECK(actor_role = 'R1_REVIEWER'),
    assigned_at TEXT NOT NULL,
    PRIMARY KEY(task_id, phase)
) STRICT;

CREATE TABLE r1_decisions (
    task_id TEXT NOT NULL,
    parameter_id TEXT NOT NULL,
    decision_revision INTEGER NOT NULL CHECK(decision_revision > 0),
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    verdict TEXT NOT NULL CHECK(verdict IN ('SAME', 'DIFFERENT', 'UNABLE_TO_JUDGE')),
    reason TEXT,
    reviewer_id TEXT NOT NULL,
    evidence_manifest_hash TEXT NOT NULL CHECK(length(evidence_manifest_hash) = 64 AND evidence_manifest_hash NOT GLOB '*[^0-9a-f]*'),
    decided_at TEXT NOT NULL,
    command_id TEXT NOT NULL UNIQUE,
    CHECK(verdict = 'SAME' OR (reason IS NOT NULL AND length(trim(reason)) > 0)),
    PRIMARY KEY(task_id, parameter_id, decision_revision),
    FOREIGN KEY(task_id, parameter_id) REFERENCES task_parameters(task_id, parameter_id)
) STRICT;

CREATE INDEX r1_decisions_latest_idx
ON r1_decisions(task_id, parameter_id, decision_revision DESC);

CREATE TABLE r1_locks (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    task_revision INTEGER NOT NULL UNIQUE CHECK(task_revision > 0),
    decision_count INTEGER NOT NULL CHECK(decision_count > 0),
    snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256) = 64 AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),
    evidence_manifest_hash TEXT NOT NULL CHECK(length(evidence_manifest_hash) = 64 AND evidence_manifest_hash NOT GLOB '*[^0-9a-f]*'),
    reviewer_id TEXT NOT NULL,
    locked_at TEXT NOT NULL,
    command_id TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE command_receipts (
    command_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    command_type TEXT NOT NULL CHECK(command_type IN ('REGISTER_TASK', 'RECORD_R1_DECISION', 'LOCK_R1')),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    response_json TEXT NOT NULL,
    response_sha256 TEXT NOT NULL CHECK(length(response_sha256) = 64 AND response_sha256 NOT GLOB '*[^0-9a-f]*'),
    task_revision INTEGER NOT NULL CHECK(task_revision >= 0),
    committed_at TEXT NOT NULL
) STRICT;

CREATE TABLE audit_outbox (
    outbox_id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    aggregate_revision INTEGER NOT NULL CHECK(aggregate_revision >= 0),
    event_type TEXT NOT NULL CHECK(event_type IN ('TASK_REGISTERED', 'R1_DECISION_RECORDED', 'R1_LOCKED')),
    command_id TEXT NOT NULL UNIQUE REFERENCES command_receipts(command_id),
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    published_at TEXT,
    UNIQUE(task_id, aggregate_revision, event_type)
) STRICT;

CREATE TRIGGER migrations_no_update
BEFORE UPDATE ON _paramguard_migrations BEGIN
    SELECT RAISE(ABORT, 'migration ledger is write-once');
END;

CREATE TRIGGER migrations_no_delete
BEFORE DELETE ON _paramguard_migrations BEGIN
    SELECT RAISE(ABORT, 'migration ledger is write-once');
END;

CREATE TRIGGER tasks_immutable_fields
BEFORE UPDATE OF task_id, workflow_mode, data_classification,
    evidence_manifest_id, evidence_manifest_hash, evidence_manifest_json,
    pipeline_spec_id, pipeline_spec_hash, pipeline_spec_json, registered_at
ON tasks BEGIN
    SELECT RAISE(ABORT, 'task identity and frozen evidence are write-once');
END;

CREATE TRIGGER tasks_no_delete
BEFORE DELETE ON tasks BEGIN
    SELECT RAISE(ABORT, 'tasks are append-preserving');
END;

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

CREATE TRIGGER task_parameters_no_update
BEFORE UPDATE ON task_parameters BEGIN
    SELECT RAISE(ABORT, 'task parameters are write-once');
END;

CREATE TRIGGER task_parameters_no_delete
BEFORE DELETE ON task_parameters BEGIN
    SELECT RAISE(ABORT, 'task parameters are write-once');
END;

CREATE TRIGGER evidence_artifacts_no_update
BEFORE UPDATE ON evidence_artifacts BEGIN
    SELECT RAISE(ABORT, 'evidence artifacts are write-once');
END;

CREATE TRIGGER evidence_artifacts_no_delete
BEFORE DELETE ON evidence_artifacts BEGIN
    SELECT RAISE(ABORT, 'evidence artifacts are write-once');
END;

CREATE TRIGGER task_assignments_no_update
BEFORE UPDATE ON task_assignments BEGIN
    SELECT RAISE(ABORT, 'task assignments are write-once');
END;

CREATE TRIGGER task_assignments_no_delete
BEFORE DELETE ON task_assignments BEGIN
    SELECT RAISE(ABORT, 'task assignments are write-once');
END;

CREATE TRIGGER r1_decisions_no_update
BEFORE UPDATE ON r1_decisions BEGIN
    SELECT RAISE(ABORT, 'R1 decision revisions are write-once');
END;

CREATE TRIGGER r1_decisions_validate_insert
BEFORE INSERT ON r1_decisions
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
      AND NEW.decision_revision = COALESCE((
          SELECT MAX(d.decision_revision) + 1
          FROM r1_decisions d
          WHERE d.task_id = NEW.task_id
            AND d.parameter_id = NEW.parameter_id
      ), 1)
) BEGIN
    SELECT RAISE(ABORT, 'R1 decision binding or revision is invalid');
END;

CREATE TRIGGER r1_decisions_no_delete
BEFORE DELETE ON r1_decisions BEGIN
    SELECT RAISE(ABORT, 'R1 decision revisions are write-once');
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

CREATE TRIGGER command_receipts_no_update
BEFORE UPDATE ON command_receipts BEGIN
    SELECT RAISE(ABORT, 'command receipts are write-once');
END;

CREATE TRIGGER command_receipts_no_delete
BEFORE DELETE ON command_receipts BEGIN
    SELECT RAISE(ABORT, 'command receipts are write-once');
END;

CREATE TRIGGER audit_outbox_no_update
BEFORE UPDATE ON audit_outbox BEGIN
    SELECT RAISE(ABORT, 'P1 audit outbox rows are write-once');
END;

CREATE TRIGGER audit_outbox_no_delete
BEFORE DELETE ON audit_outbox BEGIN
    SELECT RAISE(ABORT, 'P1 audit outbox rows are write-once');
END;
