"""empty message

Revision ID: e75c42c0a5fa
Revises: c6ab5bca36bd
Create Date: 2021-08-25 14:59:20.486332

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e75c42c0a5fa'
down_revision = 'c6ab5bca36bd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('session', sa.Column('have_new_content', sa.Boolean(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('session', 'have_new_content')
    # ### end Alembic commands ###