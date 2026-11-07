"""drop phone number

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"


def upgrade():
    op.drop_column("users", "phone_number")


def downgrade():
    op.add_column("users", sa.Column("phone_number", sa.String(20)))
