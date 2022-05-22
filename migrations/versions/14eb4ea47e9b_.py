"""empty message

Revision ID: 14eb4ea47e9b
Revises: e75c42c0a5fa
Create Date: 2021-08-25 23:34:55.291248

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '14eb4ea47e9b'
down_revision = 'e75c42c0a5fa'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('attempt', sa.Column('session_id', sa.Integer(), nullable=False))
    op.add_column('attempt', sa.Column('have_new_content_for_teacher', sa.Boolean(), nullable=False))
    op.add_column('attempt', sa.Column('have_new_content_for_student', sa.Boolean(), nullable=False))
    op.create_foreign_key(None, 'attempt', 'session', ['session_id'], ['id'])
    op.add_column('session', sa.Column('current_attempt', sa.Integer(), nullable=False))
    op.drop_column('session', 'have_new_content')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('session', sa.Column('have_new_content', sa.BOOLEAN(), autoincrement=False, nullable=False))
    op.drop_column('session', 'current_attempt')
    op.drop_constraint(None, 'attempt', type_='foreignkey')
    op.drop_column('attempt', 'have_new_content_for_student')
    op.drop_column('attempt', 'have_new_content_for_teacher')
    op.drop_column('attempt', 'session_id')
    # ### end Alembic commands ###
