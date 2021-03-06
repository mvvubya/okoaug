"""empty message

Revision ID: ee2988293086
Revises: 47289786c874
Create Date: 2018-07-09 20:10:28.202652

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ee2988293086'
down_revision = '47289786c874'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'comment', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'comment', 'report', ['report_id'], ['id'])
    op.create_foreign_key(None, 'report', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'report', 'department', ['department_id'], ['id'])
    op.create_foreign_key(None, 'user', 'status', ['status_id'], ['id'])
    op.create_foreign_key(None, 'user', 'department', ['department_id'], ['id'])
    op.create_foreign_key(None, 'user', 'role', ['role_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'report', type_='foreignkey')
    op.drop_constraint(None, 'report', type_='foreignkey')
    op.drop_constraint(None, 'comment', type_='foreignkey')
    op.drop_constraint(None, 'comment', type_='foreignkey')
    # ### end Alembic commands ###
