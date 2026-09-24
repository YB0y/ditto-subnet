"""Pin a verification replay to the quarantine policy manifest.

Revision ID: f2a8c04e6b91
Revises: 1bc9d8a6207e

A policy-version match is not the manifest. Existing rows stay null and
fail closed until a new lease snapshots the digest at authorization.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f2a8c04e6b91"
down_revision: str | Sequence[str] | None = "1bc9d8a6207e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "screening_verification_replays",
        sa.Column("manifest_digest", sa.Text(), nullable=True),
    )
    op.create_check_constraint(
        "svrp_manifest_digest_check",
        "screening_verification_replays",
        "manifest_digest IS NULL OR manifest_digest ~ '^[0-9a-f]{64}$'",
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION reject_verification_replay_binding_change()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (NEW.request_id, NEW.agent_id, NEW.quarantine_id,
                NEW.source_attempt_id, NEW.artifact_sha256,
                NEW.policy_version, NEW.manifest_digest, NEW.image_upload_id)
               IS DISTINCT FROM
               (OLD.request_id, OLD.agent_id, OLD.quarantine_id,
                OLD.source_attempt_id, OLD.artifact_sha256,
                OLD.policy_version, OLD.manifest_digest, OLD.image_upload_id) THEN
                RAISE EXCEPTION 'verification replay source binding is immutable';
            END IF;
            IF OLD.image_verified_storage_key IS NOT NULL AND
               NEW.image_verified_storage_key IS DISTINCT FROM
               OLD.image_verified_storage_key THEN
                RAISE EXCEPTION 'verification replay verified image key is immutable';
            END IF;
            IF OLD.image_verified_at IS NOT NULL AND
               NEW.image_verified_at IS DISTINCT FROM OLD.image_verified_at THEN
                RAISE EXCEPTION 'verification replay image verification is immutable';
            END IF;
            RETURN NEW;
        END;
        $$"""
    )


def downgrade() -> None:
    op.execute(
        """CREATE OR REPLACE FUNCTION reject_verification_replay_binding_change()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (NEW.request_id, NEW.agent_id, NEW.quarantine_id,
                NEW.source_attempt_id, NEW.artifact_sha256,
                NEW.policy_version, NEW.image_upload_id)
               IS DISTINCT FROM
               (OLD.request_id, OLD.agent_id, OLD.quarantine_id,
                OLD.source_attempt_id, OLD.artifact_sha256,
                OLD.policy_version, OLD.image_upload_id) THEN
                RAISE EXCEPTION 'verification replay source binding is immutable';
            END IF;
            IF OLD.image_verified_storage_key IS NOT NULL AND
               NEW.image_verified_storage_key IS DISTINCT FROM
               OLD.image_verified_storage_key THEN
                RAISE EXCEPTION 'verification replay verified image key is immutable';
            END IF;
            IF OLD.image_verified_at IS NOT NULL AND
               NEW.image_verified_at IS DISTINCT FROM OLD.image_verified_at THEN
                RAISE EXCEPTION 'verification replay image verification is immutable';
            END IF;
            RETURN NEW;
        END;
        $$"""
    )
    op.drop_constraint(
        "svrp_manifest_digest_check",
        "screening_verification_replays",
        type_="check",
    )
    op.drop_column("screening_verification_replays", "manifest_digest")
