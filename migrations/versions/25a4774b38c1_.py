"""empty message

Revision ID: 25a4774b38c1
Revises: c2fca2ca807f
Create Date: 2018-06-21 15:40:32.322887

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '25a4774b38c1'
down_revision = 'c2fca2ca807f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'report', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'report', 'department', ['department_id'], ['id'])
    op.drop_column('report', 'numfollowup')
    op.drop_column('report', 'notesfollowup')
    op.drop_column('report', 'church')
    op.drop_column('report', 'numstud')
    op.drop_column('report', 'numschool')
    op.drop_column('report', 'numchurch')
    op.drop_column('report', 'student')
    op.create_foreign_key(None, 'user', 'status', ['status_id'], ['id'])
    op.create_foreign_key(None, 'user', 'department', ['department_id'], ['id'])
    op.create_foreign_key(None, 'user', 'role', ['role_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.add_column('report', sa.Column('student', mysql.VARCHAR(length=60), nullable=True))
    op.add_column('report', sa.Column('numchurch', mysql.VARCHAR(length=60), nullable=True))
    op.add_column('report', sa.Column('numschool', mysql.TEXT(), nullable=True))
    op.add_column('report', sa.Column('numstud', mysql.TEXT(), nullable=True))
    op.add_column('report', sa.Column('church', mysql.VARCHAR(length=60), nullable=True))
    op.add_column('report', sa.Column('notesfollowup', mysql.VARCHAR(length=60), nullable=True))
    op.add_column('report', sa.Column('numfollowup', mysql.VARCHAR(length=60), nullable=True))
    op.drop_constraint(None, 'report', type_='foreignkey')
    op.drop_constraint(None, 'report', type_='foreignkey')
    # ### end Alembic commands ###
