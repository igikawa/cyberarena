"""Remember intentionally deleted bundled challenges.

Revision ID: 0003_deleted_challenge_seeds
Revises: 0002_challenge_seed_key
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_deleted_challenge_seeds"
down_revision = "0002_challenge_seed_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deleted_challenge_seeds",
        sa.Column("seed_key", sa.String(length=40), primary_key=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("deleted_challenge_seeds")
