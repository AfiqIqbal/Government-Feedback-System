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
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_panel'))
        return redirect(url_for('search'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route accessed")
    if request.method == 'POST':
        aadhar_id = request.form.get('aadhar_id')
        password = request.form.get('password')
        print(f"Login attempt - Aadhar ID: {aadhar_id}")
        print(f"Form data: {request.form}")
        
        user = User.query.filter_by(aadhar_id=aadhar_id).first()
        if user:
            print(f"User found: {user.name}")
            if check_password_hash(user.password, password):
                login_user(user)
                print(f"Login successful for user: {user.name}")
                flash(f'Welcome back, {user.name}!', 'success')
                return redirect(url_for('index'))
            else:
                print("Password verification failed")
        else:
            print("User not found")
        
        flash('Invalid credentials. Please try again.', 'error')
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
def admin_panel():
    return render_template('admin.html')

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
                    'marked_for_review': official.marked_for_review,
                    'is_flagged': official.is_flagged
                })
        
        print("Matching officials found:", len(results))
        return jsonify(results)
    except Exception as e:
        print("Error in search_officials:", str(e))
        return jsonify({'error': 'An error occurred while searching officials'}), 500

@app.route('/api/officials/<int:official_id>/feedbacks')
@login_required
def get_feedbacks(official_id):
    try:
        print(f"Getting feedbacks for official {official_id}")
        official = Official.query.get_or_404(official_id)
        feedbacks = Feedback.query.filter_by(official_id=official_id).order_by(Feedback.timestamp.desc()).all()
        print(f"Found {len(feedbacks)} feedbacks")
        
        result = [{
            'id': f.id,
            'user_name': f.user.name,
            'category': f.category,
            'rating': f.rating,
            'description': f.description,
            'timestamp': f.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for f in feedbacks]
        
        return jsonify({'feedbacks': result})
    except Exception as e:
        print(f"Error getting feedbacks: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching feedbacks'}), 500

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
        
        # Update poor ratings count
        if rating <= 2:
            official.poor_ratings_count += 1
            if official.poor_ratings_count >= 5 and not official.marked_for_review:
                official.marked_for_review = True
                print(f"Official {official.name} marked for review due to {official.poor_ratings_count} poor ratings")
        
        db.session.commit()
        print(f"Feedback submitted successfully for official {official.name}")
        
        # Return updated feedbacks
        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully',
            'official': {
                'id': official.id,
                'name': official.name,
                'position': official.position,
                'photo_url': official.photo_url,
                'rating': official.average_rating,
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged
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
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged
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
            photo_url=data.get('photo_url', 'https://via.placeholder.com/150')
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
        'is_flagged': o.is_flagged
    } for o in officials])

@app.route('/api/admin/officials/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_official(id):
    official = Official.query.get_or_404(id)
    db.session.delete(official)
    db.session.commit()
    return jsonify({'success': True})

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
                'marked_for_review': official.marked_for_review,
                'is_flagged': official.is_flagged
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
    if request.method == 'POST':
        data = request.json
        user = User(
            name=data['name'],
            aadhar_id=data['aadhar_id'],
            password=generate_password_hash(data['password']),
            role='user'
        )
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True})
    
    users = User.query.filter_by(role='user').all()
    return jsonify([{
        'id': u.aadhar_id,
        'name': u.name,
        'aadhar_id': u.aadhar_id
    } for u in users])

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
    user = User.query.filter_by(aadhar_id=aadhar_id).first_or_404()
    data = request.json
    user.password = generate_password_hash(data['password'])
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/feedbacks')
@login_required
@admin_required
def admin_feedbacks():
    official_id = request.args.get('official_id')
    query = Feedback.query
    
    if official_id:
        query = query.filter_by(official_id=official_id)
    
    feedbacks = query.order_by(Feedback.timestamp.desc()).all()
    return jsonify([{
        'id': f.id,
        'user_name': f.user.name,
        'official_name': f.official.name,
        'category': f.category,
        'rating': f.rating,
        'description': f.description,
        'timestamp': f.timestamp.strftime('%Y-%m-%d %H:%M:%S')
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
