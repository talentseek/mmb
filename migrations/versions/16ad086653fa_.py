"""empty message

Revision ID: 16ad086653fa
Revises: 320d7552ca72
Create Date: 2024-09-08 17:27:14.507672

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '16ad086653fa'
down_revision = '320d7552ca72'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('mailbox', schema=None) as batch_op:
        batch_op.add_column(sa.Column('full_name', sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column('password', sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column('added_to_server', sa.Boolean(), nullable=False))
        batch_op.add_column(sa.Column('added_to_smartlead', sa.Boolean(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('mailbox', schema=None) as batch_op:
        batch_op.drop_column('added_to_smartlead')
        batch_op.drop_column('added_to_server')
        batch_op.drop_column('password')
        batch_op.drop_column('full_name')

    # ### end Alembic commands ###
