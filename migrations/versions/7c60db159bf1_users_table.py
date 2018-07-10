"""users table

Revision ID: 7c60db159bf1
Revises: 6d5b54a11da2
Create Date: 2018-06-12 07:55:10.231418

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c60db159bf1'
down_revision = '6d5b54a11da2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('acc_status', sa.String(length=30), nullable=True))
    op.create_index(op.f('ix_user_acc_status'), 'user', ['acc_status'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_acc_status'), table_name='user')
    op.drop_column('user', 'acc_status')
    # ### end Alembic commands ###
