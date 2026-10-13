"""Store encrypted challenge flags for dynamic task materials.

Revision ID: 0004_encrypted_challenge_flags
Revises: 0003_deleted_challenge_seeds
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_encrypted_challenge_flags"
down_revision = "0003_deleted_challenge_seeds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("challenges", sa.Column("flag_encrypted", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("challenges", "flag_encrypted")
