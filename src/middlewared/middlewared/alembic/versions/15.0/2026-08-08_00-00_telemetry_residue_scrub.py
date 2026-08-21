"""Scrub telemetry residue values (the internal development record)

The transmission paths were removed in the internal development record/the internal development record; these stored values are the
last thing still claiming telemetry is on. A 13.3 config arrives here via the
supported GUI upgrade / config-restore paths with all four enabled (verified
against the production 13.3 box), so this runs at the tail of every chain
replay: fresh install, upgrade, and restore all land reporting the truth.

Revision ID: 6950c136c5ac
Revises: e8b3a5c1f972
Create Date: 2026-08-08 00:00:00.000000+00:00

"""
from alembic import op


revision = '6950c136c5ac'
down_revision = 'e8b3a5c1f972'
branch_labels = None
depends_on = None


def upgrade():
    # NULL = "never chose" for the nullable pair (is_set stays False);
    # 0 = plain off for the boolean pair; the anonstats token is an
    # iX-issued per-box identifier with zero readers -- cleared to '' (the
    # real table declares it NOT NULL, unlike the model).
    op.execute("UPDATE system_settings SET stg_crash_reporting = NULL, stg_usage_collection = NULL")
    op.execute("UPDATE system_advanced SET adv_anonstats = 0, adv_uploadcrash = 0, adv_anonstats_token = ''")


def downgrade():
    # The scrubbed values are unrecoverable by design; nothing to restore.
    pass
