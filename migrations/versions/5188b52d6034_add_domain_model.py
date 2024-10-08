"""Add Domain model

Revision ID: 5188b52d6034
Revises: 104983f120a9
Create Date: 2024-09-07 23:03:47.843537

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5188b52d6034'
down_revision = '104983f120a9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('domain',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('cloudflare_zone_id', sa.String(length=100), nullable=False),
    sa.Column('forwarding_url', sa.String(length=255), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('domain')
    # ### end Alembic commands ###
