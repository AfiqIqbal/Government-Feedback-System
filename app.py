from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///feedback.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'
login_manager.login_message = 'Please log in to access this page.'

class User(UserMixin, db.Model):
    aadhar_id = db.Column(db.String(12), primary_key=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)

    def get_id(self):
        return self.aadhar_id

class Official(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    photo_url = db.Column(db.String(200))
    average_rating = db.Column(db.Float, default=0.0)
    poor_ratings_count = db.Column(db.Integer, default=0)  # Count of ratings 1 & 2
    marked_for_review = db.Column(db.Boolean, default=False)  # True if poor_ratings_count >= 5
    is_flagged = db.Column(db.Boolean, default=False)  # True if confirmed poor service after review
    department = db.Column(db.String(100))
    office_location = db.Column(db.String(100))
    contact_email = db.Column(db.String(100))
    feedbacks = db.relationship('Feedback', backref='official', lazy=True)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_aadhar_id = db.Column(db.String(12), db.ForeignKey('user.aadhar_id'), nullable=False)
    official_id = db.Column(db.Integer, db.ForeignKey('official.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(aadhar_id):
    return User.query.get(aadhar_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        if current_user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('search'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin'))
        return redirect(url_for('search'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        aadhar_id = request.form.get('aadhar_id')
        password = request.form.get('password')
        
        if not aadhar_id or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('login'))
            
        user = User.query.get(aadhar_id)
        if user is None:
            flash('Invalid Aadhar ID or password', 'error')
            return redirect(url_for('login'))
            
        if check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')
            # Redirect admin to admin page, others to search page
            if user.role == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('search'))
        else:
            flash('Invalid Aadhar ID or password', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/search')
@login_required
def search():
    return render_template('search.html')

@app.route('/admin')
@login_required
@admin_required
def admin():
    try:
        users = User.query.filter(User.role != 'admin').all()
        officials = Official.query.all()
        feedbacks = Feedback.query.all()
        return render_template('admin.html', 
                             users=users, 
                             officials=officials, 
                             feedbacks=feedbacks)
    except Exception as e:
        flash('Error loading admin page: ' + str(e), 'error')
        return redirect(url_for('index'))

# API Routes
@app.route('/api/officials/search')
@login_required
def search_officials():
    try:
        print("Search endpoint accessed by user:", current_user.name)
        query = request.args.get('query', '').lower()
        print("Search query:", query)
        
        officials = Official.query.all()
        print("Total officials found:", len(officials))
        
        results = []
        for official in officials:
            if query in official.name.lower() or query in official.position.lower():
                results.append({
                    'id': official.id,
                    'name': official.name,
                    'position': official.position,
                    'photo_url': official.photo_url,
                    'rating': official.average_rating,
                    'poor_ratings_count': official.poor_ratings_count,
                    'marked_for_review': official.marked_for_review,
                    'is_flagged': official.is_flagged,
                    'department': official.department,
                    'office_location': official.office_location,
                    'contact_email': official.contact_email
                })
        
        print("Matching officials found:", len(results))
        return jsonify(results)
    except Exception as e:
        print("Error in search_officials:", str(e))
        return jsonify({'error': 'An error occurred while searching officials'}), 500

@app.route('/api/officials/<int:official_id>/feedbacks', methods=['GET'])
@login_required
def get_feedbacks(official_id):
    try:
        print(f"Getting feedbacks for official {official_id}")
        official = Official.query.get_or_404(official_id)
        
        # Get all feedback details
        feedbacks = []
        for feedback in official.feedbacks:
            feedbacks.append({
                'id': feedback.id,
                'user_name': feedback.user.name,
                'category': feedback.category,
                'rating': feedback.rating,
                'description': feedback.description,
                'timestamp': feedback.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        # Include official details with the response
        response = {
            'official': {
                'id': official.id,
                'name': official.name,
                'position': official.position,
                'photo_url': official.photo_url,
                'rating': official.average_rating,
                'poor_ratings_count': official.poor_ratings_count,
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged,
                'department': official.department,
                'office_location': official.office_location,
                'contact_email': official.contact_email
            },
            'feedbacks': feedbacks
        }
        
        print(f"Found {len(feedbacks)} feedbacks")
        return jsonify(response)
    except Exception as e:
        print(f"Error getting feedbacks: {str(e)}")
        return jsonify({'error': 'An error occurred while getting feedbacks'}), 500

@app.route('/api/officials/<int:official_id>/feedbacks', methods=['POST'])
@login_required
def submit_feedback(official_id):
    try:
        print(f"Submitting feedback for official {official_id} by user {current_user.name}")
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Validate required fields
        required_fields = ['category', 'rating', 'description']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
                
        # Validate rating range
        rating = int(data['rating'])
        if rating < 1 or rating > 5:
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400
            
        # Get official or return 404
        official = Official.query.get_or_404(official_id)
        
        # Create feedback
        feedback = Feedback(
            user_aadhar_id=current_user.aadhar_id,
            official_id=official_id,
            category=data['category'],
            rating=rating,
            description=data['description']
        )
        
        db.session.add(feedback)
        
        # Update official's average rating
        all_feedbacks = list(official.feedbacks) + [feedback]
        total_rating = sum(f.rating for f in all_feedbacks)
        official.average_rating = total_rating / len(all_feedbacks)
        
        # Count poor ratings (1 or 2) for this official
        poor_ratings = Feedback.query.filter(
            Feedback.official_id == official_id,
            Feedback.rating <= 2
        ).count()
        
        # Add current poor rating if applicable
        if rating <= 2:
            poor_ratings += 1
            
        # Update poor ratings count
        official.poor_ratings_count = poor_ratings
        
        # Check if official should be marked for review (5 or more poor ratings)
        if poor_ratings >= 5 and not official.marked_for_review:
            official.marked_for_review = True
            print(f"Official {official.name} marked for review due to {poor_ratings} poor ratings")
        
        db.session.commit()
        print(f"Feedback submitted successfully for official {official.name}")
        
        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully',
            'official': {
                'id': official.id,
                'name': official.name,
                'position': official.position,
                'photo_url': official.photo_url,
                'rating': official.average_rating,
                'poor_ratings_count': official.poor_ratings_count,
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged,
                'department': official.department,
                'office_location': official.office_location,
                'contact_email': official.contact_email
            }
        })
    except ValueError as e:
        print(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        print(f"Error submitting feedback: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while submitting feedback'}), 500

@app.route('/api/officials/<int:id>/confirm-poor-service', methods=['POST'])
@login_required
def confirm_poor_service(id):
    try:
        print(f"Confirming poor service for official {id} by user {current_user.name}")
        official = Official.query.get_or_404(id)
        
        if not official.marked_for_review:
            return jsonify({'error': 'Official is not marked for review'}), 400
            
        official.is_flagged = True
        db.session.commit()
        print(f"Official {official.name} has been flagged for poor service")
        
        return jsonify({
            'success': True,
            'message': 'Official has been flagged for poor service',
            'official': {
                'id': official.id,
                'name': official.name,
                'position': official.position,
                'photo_url': official.photo_url,
                'rating': official.average_rating,
                'poor_ratings_count': official.poor_ratings_count,
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged,
                'department': official.department,
                'office_location': official.office_location,
                'contact_email': official.contact_email
            }
        })
    except Exception as e:
        print(f"Error confirming poor service: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while confirming poor service'}), 500

# Admin API Routes
@app.route('/api/admin/officials', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_officials():
    if request.method == 'POST':
        data = request.json
        official = Official(
            name=data['name'],
            position=data['position'],
            photo_url=data.get('photo_url', 'https://via.placeholder.com/150'),
            department=data.get('department', ''),
            office_location=data.get('office_location', ''),
            contact_email=data.get('contact_email', '')
        )
        db.session.add(official)
        db.session.commit()
        return jsonify({'success': True})
    
    officials = Official.query.all()
    return jsonify([{
        'id': o.id,
        'name': o.name,
        'position': o.position,
        'photo_url': o.photo_url,
        'rating': o.average_rating,
        'poor_ratings_count': o.poor_ratings_count,
        'marked_for_review': o.marked_for_review,
        'is_flagged': o.is_flagged,
        'department': o.department,
        'office_location': o.office_location,
        'contact_email': o.contact_email
    } for o in officials])

@app.route('/api/admin/officials/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_official(id):
    try:
        official = Official.query.get_or_404(id)
        
        # First delete all associated feedbacks
        Feedback.query.filter_by(official_id=id).delete()
        
        # Then delete the official
        db.session.delete(official)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Official and associated feedbacks deleted successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting official: {str(e)}")
        return jsonify({'error': 'Failed to delete official'}), 500

@app.route('/api/admin/officials/<int:id>', methods=['PUT'])
@login_required
@admin_required
def update_official(id):
    try:
        print(f"Updating official {id} by admin {current_user.name}")
        official = Official.query.get_or_404(id)
        data = request.json
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Validate required fields
        required_fields = ['name', 'position']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
                
        # Update fields
        official.name = data['name']
        official.position = data['position']
        if 'photo_url' in data:
            official.photo_url = data['photo_url']
        if 'department' in data:
            official.department = data['department']
        if 'office_location' in data:
            official.office_location = data['office_location']
        if 'contact_email' in data:
            official.contact_email = data['contact_email']
            
        db.session.commit()
        print(f"Official {official.name} updated successfully")
        
        return jsonify({
            'success': True,
            'message': 'Official updated successfully',
            'official': {
                'id': official.id,
                'name': official.name,
                'position': official.position,
                'photo_url': official.photo_url,
                'rating': official.average_rating,
                'poor_ratings_count': official.poor_ratings_count,
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged,
                'department': official.department,
                'office_location': official.office_location,
                'contact_email': official.contact_email
            }
        })
    except Exception as e:
        print(f"Error updating official: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while updating official'}), 500

@app.route('/api/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
    if request.method == 'GET':
        users = User.query.filter(User.role != 'admin').all()
        return jsonify([{
            'name': user.name,
            'aadhar_id': user.aadhar_id,
            'role': user.role
        } for user in users])
    
    data = request.get_json()
    
    if not data or not all(k in data for k in ['name', 'aadhar_id', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
        
    if User.query.get(data['aadhar_id']):
        return jsonify({'error': 'User with this Aadhar ID already exists'}), 400
        
    new_user = User(
        name=data['name'],
        aadhar_id=data['aadhar_id'],
        password=generate_password_hash(data['password'], method='pbkdf2:sha256'),
        role='user'
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User added successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<aadhar_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(aadhar_id):
    user = User.query.filter_by(aadhar_id=aadhar_id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/users/<aadhar_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_password(aadhar_id):
    try:
        user = User.query.get_or_404(aadhar_id)
        new_password = 'password123'  # Default password
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        return jsonify({'message': f'Password reset successfully for user {user.name}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/feedbacks')
@login_required
@admin_required
def admin_feedbacks():
    official_id = request.args.get('official_id', type=int)
    query = Feedback.query
    
    if official_id:
        query = query.filter_by(official_id=official_id)
    
    feedbacks = query.order_by(Feedback.timestamp.desc()).all()
    return jsonify([{
        'id': f.id,
        'user_name': f.user.name,
        'user_aadhar_id': f.user.aadhar_id,
        'official_id': f.official_id,
        'official_name': f.official.name,
        'official_position': f.official.position,
        'category': f.category,
        'rating': f.rating,
        'description': f.description,
        'timestamp': f.timestamp.isoformat()
    } for f in feedbacks])

@app.route('/api/admin/feedbacks/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    
    # Update official's average rating
    official = feedback.official
    db.session.delete(feedback)
    remaining_feedbacks = Feedback.query.filter_by(official_id=official.id).all()
    
    if remaining_feedbacks:
        total_rating = sum(f.rating for f in remaining_feedbacks)
        official.average_rating = total_rating / len(remaining_feedbacks)
    else:
        official.average_rating = 0
    
    # Update poor ratings count
    if feedback.rating <= 2:
        official.poor_ratings_count -= 1
        if official.poor_ratings_count < 5:
            official.marked_for_review = False
    
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
