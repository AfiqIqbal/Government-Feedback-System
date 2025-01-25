from app import app, db, User, Official
from werkzeug.security import generate_password_hash

def init_database():
    with app.app_context():
        # Create tables
        db.create_all()

        # Add test users
        users = [
            User(
                aadhar_id='123456789012',
                password=generate_password_hash('password123'),
                name='Mukthar',
                role='user'
            ),
            User(
                aadhar_id='234567890123',
                password=generate_password_hash('password123'),
                name='Vijeesh',
                role='user'
            ),
            User(
                aadhar_id='345678901234',
                password=generate_password_hash('password123'),
                name='Jyothir',
                role='user'
            ),
            User(
                aadhar_id='456789012345',
                password=generate_password_hash('password123'),
                name='Abhijith',
                role='user'
            )
        ]

        # Add officials
        officials = [
            Official(
                name='Gouri',
                position='Revenue Department Officer',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0
            ),
            Official(
                name='Afiq',
                position='SBI Branch Manager',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0
            ),
            Official(
                name='Lakshmi',
                position='Professor',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0
            ),
            Official(
                name='Ribin',
                position='Clerk',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0
            )
        ]

        # Add to database
        try:
            # First clear existing data
            db.session.query(User).delete()
            db.session.query(Official).delete()
            
            # Add new data
            for user in users:
                db.session.add(user)
            for official in officials:
                db.session.add(official)
            db.session.commit()
            print("Test data added successfully!")
            
            # Print login information
            print("\nLogin credentials for testing:")
            for user in users:
                print(f"Name: {user.name}")
                print(f"Aadhar ID: {user.aadhar_id}")
                print(f"Password: password123")
                print("-" * 20)
            
            print("\nOfficials added:")
            for official in officials:
                print(f"Name: {official.name}")
                print(f"Position: {official.position}")
                print("-" * 20)
                
        except Exception as e:
            print(f"Error adding test data: {e}")
            db.session.rollback()

if __name__ == '__main__':
    init_database()
