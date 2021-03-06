"""empty message

Revision ID: a1fec6ee23ee
Revises: a180cce046fe
Create Date: 2018-06-28 15:05:41.554761

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1fec6ee23ee'
down_revision = 'a180cce046fe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'comment', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'comment', 'report', ['report_id'], ['id'])
    op.add_column('report', sa.Column('church', sa.String(length=60), nullable=True))
    op.add_column('report', sa.Column('notesfollowup', sa.String(length=60), nullable=True))
    op.add_column('report', sa.Column('numchurch', sa.Integer(), nullable=True))
    op.add_column('report', sa.Column('numfollowup', sa.Integer(), nullable=True))
    op.add_column('report', sa.Column('numschool', sa.Integer(), nullable=True))
    op.add_column('report', sa.Column('numstud', sa.Integer(), nullable=True))
    op.add_column('report', sa.Column('student', sa.String(length=60), nullable=True))
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
    op.drop_column('report', 'student')
    op.drop_column('report', 'numstud')
    op.drop_column('report', 'numschool')
    op.drop_column('report', 'numfollowup')
    op.drop_column('report', 'numchurch')
    op.drop_column('report', 'notesfollowup')
    op.drop_column('report', 'church')
    op.drop_constraint(None, 'comment', type_='foreignkey')
    op.drop_constraint(None, 'comment', type_='foreignkey')
    # ### end Alembic commands ###
