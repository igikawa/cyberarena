"""Clear legacy shared-lab URLs from isolated-lab challenges.

Revision ID: 0006_clear_lab_urls
Revises: 0005_admin_password_rotation
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_clear_lab_urls"
down_revision = "0005_admin_password_rotation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE challenges SET resource_url = NULL "
            "WHERE resource_url LIKE '/lab/%' AND seed_key IN ("
            "'web-01', 'web-03-sqli', 'web-04-path-traversal', "
            "'business-01', 'reverse-01', 'pwn-01'"
            ")"
        )
    )


def downgrade() -> None:
    pass
