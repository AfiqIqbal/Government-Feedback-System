from app import db

def upgrade():
    # Add sentiment_score column to feedback table
    with db.engine.connect() as conn:
        conn.execute('ALTER TABLE feedback ADD COLUMN sentiment_score FLOAT')
        conn.commit()

def downgrade():
    # Remove sentiment_score column from feedback table
    with db.engine.connect() as conn:
        conn.execute('ALTER TABLE feedback DROP COLUMN sentiment_score')
        conn.commit()
