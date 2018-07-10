"""empty message

Revision ID: 9d2ca9f56f04
Revises: 576aac6b2c65
Create Date: 2018-06-20 22:12:33.531138

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d2ca9f56f04'
down_revision = '576aac6b2c65'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'report', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'report', 'department', ['department_id'], ['id'])
    op.add_column('user', sa.Column('is_active', sa.Boolean(), nullable=True))
    op.create_foreign_key(None, 'user', 'role', ['role_id'], ['id'])
    op.create_foreign_key(None, 'user', 'status', ['status_id'], ['id'])
    op.create_foreign_key(None, 'user', 'department', ['department_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_column('user', 'is_active')
    op.drop_constraint(None, 'report', type_='foreignkey')
    op.drop_constraint(None, 'report', type_='foreignkey')
    # ### end Alembic commands ###
