"""empty message

Revision ID: 05e0c14efc8b
Revises: 52959204b358
Create Date: 2021-10-12 08:32:52.377613

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '05e0c14efc8b'
down_revision = '52959204b358'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('problem', sa.Column('creation_date', sa.DateTime(), nullable=True))
    op.add_column('problem', sa.Column('is_hide', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('problem', 'is_hide')
    op.drop_column('problem', 'creation_date')
    # ### end Alembic commands ###