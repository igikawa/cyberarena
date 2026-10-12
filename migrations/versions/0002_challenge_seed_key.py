"""Add stable keys for bundled challenge seeds.

Revision ID: 0002_challenge_seed_key
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_challenge_seed_key"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("challenges", sa.Column("seed_key", sa.String(length=40), nullable=True))
    op.create_unique_constraint("uq_challenges_seed_key", "challenges", ["seed_key"])


def downgrade() -> None:
    op.drop_constraint("uq_challenges_seed_key", "challenges", type_="unique")
    op.drop_column("challenges", "seed_key")
