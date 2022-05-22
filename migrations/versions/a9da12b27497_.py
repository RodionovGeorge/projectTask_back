"""empty message

Revision ID: a9da12b27497
Revises: 633da2c5dd23
Create Date: 2021-08-23 11:31:19.321662

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a9da12b27497'
down_revision = '633da2c5dd23'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('problem', sa.Column('problem_complexity_is', sa.Integer(), nullable=True))
    op.add_column('problem', sa.Column('last_admitting_attempt', sa.DateTime(), nullable=True))
    op.alter_column('problem', 'problem_status_id',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.create_foreign_key(None, 'problem', 'problem_complexity', ['problem_complexity_is'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'problem', type_='foreignkey')
    op.alter_column('problem', 'problem_status_id',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.drop_column('problem', 'last_admitting_attempt')
    op.drop_column('problem', 'problem_complexity_is')
    # ### end Alembic commands ###