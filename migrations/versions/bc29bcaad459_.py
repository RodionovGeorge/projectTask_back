"""empty message

Revision ID: bc29bcaad459
Revises: 04e9c792ba85
Create Date: 2021-08-10 11:02:32.307306

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bc29bcaad459'
down_revision = '04e9c792ba85'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('new_password_code', sa.Column('last_user_attempt_time', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('new_password_code', 'last_user_attempt_time')
    # ### end Alembic commands ###