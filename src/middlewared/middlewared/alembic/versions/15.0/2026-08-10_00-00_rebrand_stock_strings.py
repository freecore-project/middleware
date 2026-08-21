"""Rebrand the 13.3 stock strings that survive an in-place upgrade (the internal development record)

`factory-v1.db` already ships both values correct, so a fresh install is clean. An
in-place 13.3 -> 15.0 upgrade keeps the rows it already had, and 13.3's stock values
are 'Welcome to TrueNAS' and 'TrueNAS Server'. Nothing rewrote them, so both survived
onto surfaces every operator and every SMB client sees. The in-place upgrade is a
published path, so this is not a corner case.

Both columns were found by scanning all 105 tables of a real upgraded box for
TrueNAS/FreeNAS/iXsystems strings; these two were the only hits.

Revision ID: d4a1e8b70c53
Revises: a7f2c9d4e610
Create Date: 2026-08-10 00:00:00.000000+00:00

"""
from alembic import op


revision = 'd4a1e8b70c53'
down_revision = 'a7f2c9d4e610'
branch_labels = None
depends_on = None


def upgrade():
    # Rename, never overwrite. Each row is rewritten only when it still holds the exact
    # string 13.3 shipped, so a banner the operator wrote, an empty one, or one that
    # already says FreeCORE is left alone. The production 13.3 box carries
    # '<operator-defined value>' and 'zfs' for these two and must come through untouched.
    op.execute(
        "UPDATE system_advanced SET adv_motd = 'Welcome to FreeCORE' "
        "WHERE adv_motd = 'Welcome to TrueNAS'"
    )
    op.execute(
        "UPDATE services_cifs SET cifs_srv_description = 'FreeCORE Server' "
        "WHERE cifs_srv_description = 'TrueNAS Server'"
    )


def downgrade():
    # True inverse, guarded the same way so a value set by hand is not clobbered.
    op.execute(
        "UPDATE system_advanced SET adv_motd = 'Welcome to TrueNAS' "
        "WHERE adv_motd = 'Welcome to FreeCORE'"
    )
    op.execute(
        "UPDATE services_cifs SET cifs_srv_description = 'TrueNAS Server' "
        "WHERE cifs_srv_description = 'FreeCORE Server'"
    )
