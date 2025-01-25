from app import app, db, User, Official, Feedback
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_database():
    with app.app_context():
        try:
            print("Dropping all tables...")
            db.drop_all()
            print("Creating tables...")
            db.create_all()

            # First clear existing data
            db.session.query(User).delete()
            db.session.query(Official).delete()
            db.session.query(Feedback).delete()

            print("\nCreating admin user...")
            # Add admin user
            admin_user = User(
                aadhar_id='999999999999',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                name='Admin',
                role='admin'
            )
            db.session.add(admin_user)

            print("\nCreating regular users...")
            # Add test users with their details
            users_data = [
                {
                    'aadhar_id': '123456789012',
                    'password': 'password123',
                    'name': 'Mukthar Ahmed',
                    'role': 'user'
                },
                {
                    'aadhar_id': '234567890123',
                    'password': 'password123',
                    'name': 'Vijeesh Kumar',
                    'role': 'user'
                },
                {
                    'aadhar_id': '345678901234',
                    'password': 'password123',
                    'name': 'Jyothir Lal',
                    'role': 'user'
                },
                {
                    'aadhar_id': '456789012345',
                    'password': 'password123',
                    'name': 'Abhijith Raj',
                    'role': 'user'
                }
            ]

            for user_data in users_data:
                user = User(
                    aadhar_id=user_data['aadhar_id'],
                    password=generate_password_hash(user_data['password'], method='pbkdf2:sha256'),
                    name=user_data['name'],
                    role=user_data['role']
                )
                db.session.add(user)
                print(f"Added user: {user.name}")

            print("\nCreating officials...")
            # Add officials with their details
            officials_data = [
                {
                    'name': 'Gouri Shankar',
                    'position': 'Revenue Department Officer',
                    'photo_url': 'https://example.com/photos/gouri.jpg',
                    'department': 'Revenue',
                    'office_location': 'Trivandrum',
                    'contact_email': 'gouri.shankar@gov.in'
                },
                {
                    'name': 'Afiq Rahman',
                    'position': 'SBI Branch Manager',
                    'photo_url': 'https://example.com/photos/afiq.jpg',
                    'department': 'Banking',
                    'office_location': 'Kochi',
                    'contact_email': 'afiq.rahman@sbi.co.in'
                },
                {
                    'name': 'Lakshmi Devi',
                    'position': 'Professor',
                    'photo_url': 'https://example.com/photos/lakshmi.jpg',
                    'department': 'Education',
                    'office_location': 'Calicut',
                    'contact_email': 'lakshmi.devi@edu.in'
                },
                {
                    'name': 'Ribin Thomas',
                    'position': 'Municipal Corporation Clerk',
                    'photo_url': 'https://example.com/photos/ribin.jpg',
                    'department': 'Municipal Administration',
                    'office_location': 'Kollam',
                    'contact_email': 'ribin.thomas@municipality.gov.in'
                }
            ]

            for official_data in officials_data:
                official = Official(
                    name=official_data['name'],
                    position=official_data['position'],
                    photo_url=official_data['photo_url'],
                    average_rating=0.0,
                    poor_ratings_count=0,
                    marked_for_review=False,
                    is_flagged=False,
                    department=official_data['department'],
                    office_location=official_data['office_location'],
                    contact_email=official_data['contact_email']
                )
                db.session.add(official)
                print(f"Added official: {official.name}")

            # Commit all changes
            db.session.commit()
            print("\nTest data added successfully!")

            # Print login credentials for reference
            print("\nAdmin Login:")
            print(f"Aadhar ID: {admin_user.aadhar_id}")
            print(f"Password: admin123")
            print("-" * 20)

            print("\nUser Login credentials:")
            for user_data in users_data:
                print(f"Name: {user_data['name']}")
                print(f"Aadhar ID: {user_data['aadhar_id']}")
                print(f"Password: {user_data['password']}")
                print("-" * 20)

            print("\nOfficials added:")
            for official_data in officials_data:
                print(f"Name: {official_data['name']}")
                print(f"Position: {official_data['position']}")
                print(f"Department: {official_data['department']}")
                print(f"Location: {official_data['office_location']}")
                print("-" * 20)

        except Exception as e:
            print(f"Error: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()

if __name__ == '__main__':
    init_database()
