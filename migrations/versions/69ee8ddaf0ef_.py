"""empty message

Revision ID: 69ee8ddaf0ef
Revises: c511756f621a
Create Date: 2018-06-15 02:17:15.674703

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '69ee8ddaf0ef'
down_revision = 'c511756f621a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('department',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=60), nullable=True),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('role',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=60), nullable=True),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('status',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=60), nullable=True),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.add_column('user', sa.Column('department_id', sa.Integer(), nullable=True))
    op.add_column('user', sa.Column('is_admin', sa.Boolean(), nullable=True))
    op.add_column('user', sa.Column('role_id', sa.Integer(), nullable=True))
    op.add_column('user', sa.Column('status_id', sa.Integer(), nullable=True))
    op.drop_index('ix_user_acc_status', table_name='user')
    op.drop_index('ix_user_department', table_name='user')
    op.drop_index('ix_user_user_role', table_name='user')
    op.create_foreign_key(None, 'user', 'department', ['department_id'], ['id'])
    op.create_foreign_key(None, 'user', 'status', ['status_id'], ['id'])
    op.create_foreign_key(None, 'user', 'role', ['role_id'], ['id'])
    op.drop_column('user', 'acc_status')
    op.drop_column('user', 'department')
    op.drop_column('user', 'user_role')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('user_role', sa.VARCHAR(length=50), nullable=True))
    op.add_column('user', sa.Column('department', sa.VARCHAR(length=50), nullable=True))
    op.add_column('user', sa.Column('acc_status', sa.VARCHAR(length=30), nullable=True))
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.drop_constraint(None, 'user', type_='foreignkey')
    op.create_index('ix_user_user_role', 'user', ['user_role'], unique=False)
    op.create_index('ix_user_department', 'user', ['department'], unique=False)
    op.create_index('ix_user_acc_status', 'user', ['acc_status'], unique=False)
    op.drop_column('user', 'status_id')
    op.drop_column('user', 'role_id')
    op.drop_column('user', 'is_admin')
    op.drop_column('user', 'department_id')
    op.drop_table('status')
    op.drop_table('role')
    op.drop_table('department')
    # ### end Alembic commands ###
