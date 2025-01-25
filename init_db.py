from app import app, db, User, Official
from werkzeug.security import generate_password_hash

def init_database():
    with app.app_context():
        # Drop all tables
        print("Dropping all tables...")
        db.drop_all()
        
        # Create tables
        print("Creating tables...")
        db.create_all()

        # Add admin user
        admin_user = User(
            aadhar_id='999999999999',
            password=generate_password_hash('admin123'),
            name='Admin',
            role='admin'
        )

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
                average_rating=0.0,
                poor_ratings_count=0,
                marked_for_review=False,
                is_flagged=False
            ),
            Official(
                name='Afiq',
                position='SBI Branch Manager',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0,
                poor_ratings_count=0,
                marked_for_review=False,
                is_flagged=False
            ),
            Official(
                name='Lakshmi',
                position='Professor',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0,
                poor_ratings_count=0,
                marked_for_review=False,
                is_flagged=False
            ),
            Official(
                name='Ribin',
                position='Clerk',
                photo_url='https://via.placeholder.com/150',
                average_rating=0.0,
                poor_ratings_count=0,
                marked_for_review=False,
                is_flagged=False
            )
        ]

        # Add to database
        try:
            # First clear existing data
            db.session.query(User).delete()
            db.session.query(Official).delete()
            
            # Add new data
            db.session.add(admin_user)
            for user in users:
                db.session.add(user)
            for official in officials:
                db.session.add(official)
            db.session.commit()
            print("Test data added successfully!")
            
            # Print login information
            print("\nAdmin Login:")
            print("Aadhar ID: 999999999999")
            print("Password: admin123")
            print("-" * 20)
            
            print("\nUser Login credentials:")
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
