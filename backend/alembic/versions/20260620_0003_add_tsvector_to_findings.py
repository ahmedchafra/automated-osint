"""Add tsvector column to findings for full-text search

Revision ID: 20260620_0003_add_tsvector_to_findings
Revises: 20260618_0002_add_target_usernames
Create Date: 2026-06-20 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20260620_0003_add_tsvector_to_findings'
down_revision = '20260618_0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add tsvector column
    op.add_column('findings', sa.Column('search_vector', postgresql.TSVECTOR(), nullable=True))

    # Create GIN index on the tsvector column
    op.create_index('ix_findings_search_vector', 'findings', ['search_vector'], unique=False, postgresql_using='gin')

    # Create trigger function to keep search_vector updated
    op.execute("""
        CREATE OR REPLACE FUNCTION update_findings_search_vector()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.search_vector :=
                to_tsvector('english', COALESCE(NEW.entity_value, '') || ' ' ||
                            COALESCE(NEW.raw_data::text, '') || ' ' ||
                            COALESCE(NEW.normalized_data::text, ''));
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Create trigger
    # asyncpg rejects multiple SQL commands in one prepared statement, so the
    # idempotent drop and create must be executed separately.
    op.execute("DROP TRIGGER IF EXISTS findings_search_vector_trigger ON findings")
    op.execute("""
        CREATE TRIGGER findings_search_vector_trigger
        BEFORE INSERT OR UPDATE ON findings
        FOR EACH ROW EXECUTE FUNCTION update_findings_search_vector()
    """)

    # Update existing rows
    op.execute("""
        UPDATE findings
        SET search_vector = to_tsvector('english', COALESCE(entity_value, '') || ' ' ||
                                    COALESCE(raw_data::text, '') || ' ' ||
                                    COALESCE(normalized_data::text, ''));
    """)


def downgrade() -> None:
    # Drop trigger
    op.execute("""
        DROP TRIGGER IF EXISTS findings_search_vector_trigger ON findings;
    """)

    # Drop function
    op.execute("""
        DROP FUNCTION IF EXISTS update_findings_search_vector();
    """)

    # Drop index
    op.drop_index('ix_findings_search_vector', table_name='findings')

    # Drop column
    op.drop_column('findings', 'search_vector')
