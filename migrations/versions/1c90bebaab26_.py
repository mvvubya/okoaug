"""empty message

Revision ID: 1c90bebaab26
Revises: c97f4ffae13d
Create Date: 2018-06-21 15:49:34.700321

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1c90bebaab26'
down_revision = 'c97f4ffae13d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'report', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'report', 'department', ['department_id'], ['id'])
    op.create_foreign_key(None, 'user', 'department', ['department_id'], ['id'])
    op.create_foreign_key(None, 'user', 'status', ['status_id'], ['id'])
    op.create_foreign_key(None, 'user', 'role', ['role_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'report', type_='foreignkey')
    op.drop_constraint(None, 'report', type_='foreignkey')
    # ### end Alembic commands ###
