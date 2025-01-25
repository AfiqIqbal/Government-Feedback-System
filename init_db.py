from app import app, db, User, Official
from werkzeug.security import generate_password_hash

def init_database():
    with app.app_context():
        # Create tables
        db.create_all()

        # Add test user
        test_user = User(
            aadhar_id='123456789012',
            password=generate_password_hash('password123'),
            name='Test User',
            role='user'
        )

        # Add test officials
        officials = [
            Official(
                name='John Smith',
                position='District Collector',
                photo_url='https://via.placeholder.com/150',
                average_rating=4.5
            ),
            Official(
                name='Mary Johnson',
                position='Revenue Officer',
                photo_url='https://via.placeholder.com/150',
                average_rating=4.2
            ),
            Official(
                name='Robert Wilson',
                position='Municipal Commissioner',
                photo_url='https://via.placeholder.com/150',
                average_rating=3.8
            )
        ]

        # Add to database
        try:
            db.session.add(test_user)
            for official in officials:
                db.session.add(official)
            db.session.commit()
            print("Test data added successfully!")
        except Exception as e:
            print(f"Error adding test data: {e}")
            db.session.rollback()

if __name__ == '__main__':
    init_database()
