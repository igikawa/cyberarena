"""Require existing administrators to replace their initial password.

Revision ID: 0005_admin_password_rotation
Revises: 0004_encrypted_challenge_flags
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_admin_password_rotation"
down_revision = "0004_encrypted_challenge_flags"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("must_change_password", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.execute(sa.text("UPDATE users SET must_change_password = TRUE WHERE is_admin = TRUE"))


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
