"""empty message

Revision ID: ce0960ade929
Revises: d39efca8b411
Create Date: 2022-01-22 13:50:00.326422

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ce0960ade929'
down_revision = 'd39efca8b411'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('student_attempt_status',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('teacher_feedback_status',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('commentary', sa.Column('is_new_for_student', sa.Boolean(), nullable=True))
    op.add_column('commentary', sa.Column('is_new_for_teacher', sa.Boolean(), nullable=True))
    op.drop_column('session', 'isClose')
    op.drop_column('session', 'have_new_content_for_student')
    op.drop_column('session', 'current_attempt')
    op.drop_column('session', 'have_new_content_for_teacher')
    op.add_column('student_attempt', sa.Column('status_id', sa.Integer(), nullable=True))
    op.execute("UPDATE student_attempt SET status_id=3")
    op.alter_column('student_attempt', 'status_id', nullable=False)
    op.create_foreign_key(None, 'student_attempt', 'student_attempt_status', ['status_id'], ['id'])
    op.drop_column('student_attempt', 'attempt_number')
    op.add_column('teacher_feedback', sa.Column('status_id', sa.Integer(), nullable=True))
    op.execute("UPDATE teacher_feedback SET status_id=1")
    op.alter_column('teacher_feedback', 'status_id', nullable=False)
    op.create_foreign_key(None, 'teacher_feedback', 'teacher_feedback_status', ['status_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'teacher_feedback', type_='foreignkey')
    op.drop_column('teacher_feedback', 'status_id')
    op.add_column('student_attempt', sa.Column('attempt_number', sa.INTEGER(), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'student_attempt', type_='foreignkey')
    op.drop_column('student_attempt', 'status_id')
    op.add_column('session', sa.Column('have_new_content_for_teacher', sa.BOOLEAN(), autoincrement=False, nullable=False))
    op.add_column('session', sa.Column('current_attempt', sa.INTEGER(), autoincrement=False, nullable=False))
    op.add_column('session', sa.Column('have_new_content_for_student', sa.BOOLEAN(), autoincrement=False, nullable=False))
    op.add_column('session', sa.Column('isClose', sa.BOOLEAN(), autoincrement=False, nullable=True))
    op.drop_column('commentary', 'is_new_for_teacher')
    op.drop_column('commentary', 'is_new_for_student')
    op.drop_table('teacher_feedback_status')
    op.drop_table('student_attempt_status')
    # ### end Alembic commands ###