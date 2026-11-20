"""Store custom lab image build state on challenges.

Revision ID: 0007_custom_lab_images
Revises: 0006_clear_lab_urls
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_custom_lab_images"
down_revision = "0006_clear_lab_urls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("challenges", sa.Column("lab_image_ref", sa.String(160), nullable=True))
    op.add_column("challenges", sa.Column("lab_build_status", sa.String(16), nullable=True))
    op.add_column("challenges", sa.Column("lab_build_error", sa.String(500), nullable=True))
    op.add_column("challenges", sa.Column("lab_source_archive", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("challenges", "lab_source_archive")
    op.drop_column("challenges", "lab_build_error")
    op.drop_column("challenges", "lab_build_status")
    op.drop_column("challenges", "lab_image_ref")
