from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Download NLTK data if not already downloaded
try:
    nltk.data.find('sentiment/vader_lexicon.zip')
except LookupError:
    nltk.download('vader_lexicon')

# Initialize NLTK's VADER sentiment analyzer
sia = SentimentIntensityAnalyzer()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///feedback.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Configuration
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
    feedbacks = db.relationship('Feedback', backref='user', lazy=True, cascade='all, delete')

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
    feedbacks = db.relationship('Feedback', backref='official', lazy=True, cascade='all, delete')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_aadhar_id = db.Column(db.String(12), db.ForeignKey('user.aadhar_id', ondelete='CASCADE'), nullable=False)
    official_id = db.Column(db.Integer, db.ForeignKey('official.id', ondelete='CASCADE'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sentiment_score = db.Column(db.Float)  # New column for sentiment score
    media_files = db.relationship('FeedbackMedia', backref='feedback', lazy=True, cascade='all, delete-orphan')

class FeedbackMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    feedback_id = db.Column(db.Integer, db.ForeignKey('feedback.id', ondelete='CASCADE'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)  # 'image' or 'video'
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    return 'video' if ext in {'mp4', 'mov', 'avi'} else 'image'

def analyze_sentiment(text):
    """
    Analyze the sentiment of given text using NLTK's VADER sentiment analyzer
    Returns a float between -1 (most negative) and 1 (most positive)
    """
    try:
        if not text:
            return 0.0
            
        # Get sentiment scores
        sentiment = sia.polarity_scores(text)
        
        # Log for debugging
        logger.debug(f"Sentiment analysis for text: {text[:100]}...")  # Only print first 100 chars
        logger.debug(f"Sentiment scores: {sentiment}")
        
        # Return compound score which is normalized between -1 and 1
        return sentiment['compound']
    except Exception as e:
        logger.error(f"Error in sentiment analysis: {str(e)}")
        logger.error(f"Text that caused error: {text[:100]}...")  # Only print first 100 chars
        return 0.0

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin'))
        return redirect(url_for('search'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin'))
        return redirect(url_for('search'))
    
    if request.method == 'POST':
        aadhar_id = request.form.get('aadhar_id')
        password = request.form.get('password')
        
        user = User.query.filter_by(aadhar_id=aadhar_id).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')
            # Redirect admin to admin page, others to search page
            if user.role == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('search'))
        else:
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

@app.route('/uploads/<path:filename>')
@login_required
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# API Routes
@app.route('/api/officials/search')
@login_required
def search_officials():
    try:
        logger.debug("Search endpoint accessed by user:", current_user.name)
        query = request.args.get('query', '').lower()
        logger.debug("Search query:", query)
        
        officials = Official.query.all()
        logger.debug("Total officials found:", len(officials))
        
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
                    'is_flagged': False,
                    'department': official.department,
                    'office_location': official.office_location,
                    'contact_email': official.contact_email
                })
        
        logger.debug("Matching officials found:", len(results))
        return jsonify(results)
    except Exception as e:
        logger.error("Error in search_officials:", str(e))
        return jsonify({'error': 'An error occurred while searching officials'}), 500

@app.route('/api/officials/<int:official_id>/feedbacks', methods=['GET'])
@login_required
def get_feedbacks(official_id):
    try:
        # Get official or return 404
        official = Official.query.get_or_404(official_id)
        
        # Get all feedbacks for this official
        feedbacks = Feedback.query.filter_by(official_id=official_id).order_by(Feedback.timestamp.desc()).all()
        
        feedback_list = []
        for feedback in feedbacks:
            # Get user who submitted the feedback
            user = User.query.get(feedback.user_aadhar_id)
            
            # Get media files for this feedback
            media_files = [{
                'id': media.id,
                'file_path': url_for('serve_file', filename=media.file_path, _external=True),
                'file_type': media.file_type
            } for media in feedback.media_files]
            
            feedback_data = {
                'id': feedback.id,
                'user': {
                    'aadhar_id': user.aadhar_id,
                    'name': user.name
                },
                'category': feedback.category,
                'rating': feedback.rating,
                'description': feedback.description,
                'timestamp': feedback.timestamp.isoformat(),
                'sentiment_score': feedback.sentiment_score,
                'media_files': media_files
            }
            feedback_list.append(feedback_data)
        
        return jsonify({
            'success': True,
            'feedbacks': feedback_list
        })
    except Exception as e:
        logger.error("Error in get_feedbacks:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/officials/<int:official_id>/feedbacks', methods=['POST'])
@login_required
def submit_feedback(official_id):
    try:
        data = request.form
        files = request.files.getlist('files')
        
        # Validate input
        if not all(key in data for key in ['category', 'rating', 'description']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            rating = int(data['rating'])
            if rating < 1 or rating > 5:
                return jsonify({'error': 'Rating must be between 1 and 5'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid rating value'}), 400
        
        # Get official
        official = Official.query.get_or_404(official_id)
        
        # Analyze sentiment
        sentiment_score = analyze_sentiment(data['description'])
        logger.debug(f"Calculated sentiment score: {sentiment_score}")  # Debug log
        
        # Create feedback
        feedback = Feedback(
            user_aadhar_id=current_user.aadhar_id,
            official_id=official_id,
            category=data['category'],
            rating=rating,
            description=data['description'],
            sentiment_score=sentiment_score
        )
        
        # Handle file uploads
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                media = FeedbackMedia(
                    file_path=filename,
                    file_type=get_file_type(filename)
                )
                feedback.media_files.append(media)
        
        db.session.add(feedback)
        
        # Update official's statistics
        total_feedbacks = len(official.feedbacks)
        new_average = ((official.average_rating * total_feedbacks) + rating) / (total_feedbacks + 1)
        official.average_rating = new_average
        
        if rating <= 2:
            official.poor_ratings_count += 1
            if official.poor_ratings_count >= 5:
                official.marked_for_review = True
        
        db.session.commit()
        
        # Return the created feedback with sentiment score and official data
        return jsonify({
            'message': 'Feedback submitted successfully',
            'feedback': {
                'id': feedback.id,
                'category': feedback.category,
                'rating': feedback.rating,
                'description': feedback.description,
                'sentiment_score': feedback.sentiment_score,
                'timestamp': feedback.timestamp.isoformat(),
                'user': {
                    'name': current_user.name
                },
                'media_files': [{
                    'file_path': url_for('serve_file', filename=media.file_path, _external=True),
                    'file_type': media.file_type
                } for media in feedback.media_files]
            },
            'official': {
                'id': official.id,
                'name': official.name,
                'position': official.position,
                'photo_url': official.photo_url,
                'average_rating': official.average_rating,
                'poor_ratings_count': official.poor_ratings_count,
                'marked_for_review': official.marked_for_review,
                'is_flagged': False,
                'department': official.department,
                'office_location': official.office_location,
                'contact_email': official.contact_email
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in submit_feedback: {str(e)}")  # Debug log
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/officials/<int:id>/confirm-poor-service', methods=['POST'])
@login_required
def confirm_poor_service(id):
    try:
        logger.debug(f"Confirming poor service for official {id} by user {current_user.name}")
        official = Official.query.get_or_404(id)
        
        if not official.marked_for_review:
            return jsonify({'error': 'Official is not marked for review'}), 400
            
        official.is_flagged = True
        db.session.commit()
        logger.debug(f"Official {official.name} has been flagged for poor service")
        
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
        logger.error(f"Error confirming poor service: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while confirming poor service'}), 500

# Admin API Routes
@app.route('/api/admin/officials', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_officials():
    try:
        if request.method == 'POST':
            data = request.json
            if not data.get('name') or not data.get('position'):
                return jsonify({
                    'success': False,
                    'error': 'Name and position are required'
                }), 400

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
            
            # Return the new official's ID along with success
            return jsonify({
                'success': True,
                'id': official.id,
                'message': 'Official added successfully'
            })
        
        officials = Official.query.all()
        return jsonify([{
            'id': o.id,
            'name': o.name,
            'position': o.position,
            'photo_url': o.photo_url,
            'rating': o.average_rating,
            'poor_ratings_count': o.poor_ratings_count,
            'marked_for_review': o.marked_for_review,
            'is_flagged': False,
            'department': o.department,
            'office_location': o.office_location,
            'contact_email': o.contact_email
        } for o in officials])
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in admin_officials: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while managing officials'
        }), 500

@app.route('/api/admin/officials/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_official(id):
    try:
        logger.debug(f"Attempting to delete official {id}")
        official = Official.query.get_or_404(id)
        
        # First delete all associated feedbacks
        feedbacks = Feedback.query.filter_by(official_id=id).all()
        logger.debug(f"Found {len(feedbacks)} feedbacks to delete for official {id}")
        
        for feedback in feedbacks:
            try:
                # Delete associated media files
                for media in feedback.media_files:
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], media.file_path)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            logger.debug(f"Deleted media file: {file_path}")
                    except Exception as media_error:
                        logger.warning(f"Warning: Error deleting media file for feedback {feedback.id}: {str(media_error)}")
                        continue
                
                db.session.delete(feedback)
                logger.debug(f"Deleted feedback {feedback.id}")
            except Exception as feedback_error:
                logger.error(f"Warning: Error deleting feedback {feedback.id}: {str(feedback_error)}")
                continue
        
        # Then delete the official
        db.session.delete(official)
        db.session.commit()
        logger.debug(f"Successfully deleted official {id} and all associated data")
        
        return jsonify({
            'success': True,
            'message': 'Official and associated feedbacks deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting official {id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to delete official: {str(e)}'
        }), 500

@app.route('/api/admin/officials/<int:id>', methods=['PUT'])
@login_required
@admin_required
def update_official(id):
    try:
        logger.debug(f"Updating official {id} by admin {current_user.name}")
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
        logger.debug(f"Official {official.name} updated successfully")
        
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
                'is_flagged': False,
                'department': official.department,
                'office_location': official.office_location,
                'contact_email': official.contact_email
            }
        })
    except Exception as e:
        logger.error(f"Error updating official: {str(e)}")
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
        logger.error(f"Error adding user: {str(e)}")
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
        logger.error(f"Error resetting password: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/feedbacks', methods=['GET'])
@login_required
@admin_required
def admin_feedbacks():
    try:
        logger.info("Loading admin feedbacks")
        official_id = request.args.get('official_id', type=int)
        
        # Build query with joins to ensure we have all related data
        try:
            query = db.session.query(Feedback)\
                .join(User, Feedback.user_aadhar_id == User.aadhar_id)\
                .join(Official, Feedback.official_id == Official.id)\
                .options(db.joinedload(Feedback.media_files))
        except Exception as db_error:
            logger.error(f"Database query error: {str(db_error)}")
            return jsonify({'error': f'Database error: {str(db_error)}'}), 500
        
        if official_id:
            logger.info(f"Filtering feedbacks for official_id: {official_id}")
            query = query.filter(Feedback.official_id == official_id)
            
        try:
            feedbacks = query.order_by(Feedback.timestamp.desc()).all()
            logger.info(f"Found {len(feedbacks)} feedbacks")
        except Exception as query_error:
            logger.error(f"Error executing feedback query: {str(query_error)}")
            return jsonify({'error': f'Error retrieving feedbacks: {str(query_error)}'}), 500
        
        feedback_list = []
        
        # Calculate sentiment statistics
        sentiment_stats = {
            'positive': 0,
            'negative': 0,
            'neutral': 0,
            'total_sentiment': 0,
            'average_sentiment': 0,
            'by_category': {}
        }
        
        for feedback in feedbacks:
            try:
                # Get media files
                media_files = []
                for media in feedback.media_files:
                    media_files.append({
                        'file_path': url_for('serve_file', filename=media.file_path, _external=True),
                        'file_type': media.file_type
                    })
                
                # Update sentiment statistics
                sentiment_score = feedback.sentiment_score or 0
                if sentiment_score > 0.05:
                    sentiment_stats['positive'] += 1
                elif sentiment_score < -0.05:
                    sentiment_stats['negative'] += 1
                else:
                    sentiment_stats['neutral'] += 1
                    
                sentiment_stats['total_sentiment'] += sentiment_score
                
                # Update category statistics
                if feedback.category not in sentiment_stats['by_category']:
                    sentiment_stats['by_category'][feedback.category] = {
                        'count': 0,
                        'total_sentiment': 0,
                        'average_sentiment': 0
                    }
                cat_stats = sentiment_stats['by_category'][feedback.category]
                cat_stats['count'] += 1
                cat_stats['total_sentiment'] += sentiment_score
                cat_stats['average_sentiment'] = cat_stats['total_sentiment'] / cat_stats['count']
                
                # Create feedback data
                feedback_data = {
                    'id': feedback.id,
                    'user': {
                        'aadhar_id': feedback.user.aadhar_id,
                        'name': feedback.user.name
                    },
                    'official': {
                        'id': feedback.official.id,
                        'name': feedback.official.name,
                        'position': feedback.official.position,
                        'photo_url': feedback.official.photo_url
                    },
                    'category': feedback.category,
                    'rating': feedback.rating,
                    'description': feedback.description,
                    'timestamp': feedback.timestamp.isoformat(),
                    'sentiment_score': sentiment_score,
                    'media_files': media_files
                }
                feedback_list.append(feedback_data)
            except Exception as inner_e:
                print(f"Error processing feedback {feedback.id}: {str(inner_e)}")
                continue
        
        # Calculate overall average sentiment
        if feedback_list:
            sentiment_stats['average_sentiment'] = sentiment_stats['total_sentiment'] / len(feedback_list)
        
        print(f"Successfully processed {len(feedback_list)} feedbacks")
        return jsonify({
            'feedbacks': feedback_list,
            'sentiment_stats': sentiment_stats
        })
        
    except Exception as e:
        print(f"Error in admin_feedbacks: {str(e)}")
        return jsonify({
            'error': str(e),
            'feedbacks': [],
            'sentiment_stats': {
                'positive': 0,
                'negative': 0,
                'neutral': 0,
                'total_sentiment': 0,
                'average_sentiment': 0,
                'by_category': {}
            }
        }), 500

@app.route('/api/admin/feedbacks/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_feedback(id):
    try:
        feedback = Feedback.query.get_or_404(id)
        official = Official.query.get(feedback.official_id)
        
        # Delete associated media files
        for media in feedback.media_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], media.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete feedback (will cascade delete media records)
        db.session.delete(feedback)
        
        # Recalculate official's average rating
        remaining_feedbacks = Feedback.query.filter_by(official_id=official.id).all()
        if remaining_feedbacks:
            total_rating = sum(f.rating for f in remaining_feedbacks)
            official.average_rating = total_rating / len(remaining_feedbacks)
        else:
            official.average_rating = 0
            
        # Recalculate poor ratings count
        poor_ratings = Feedback.query.filter(
            Feedback.official_id == official.id,
            Feedback.rating <= 2
        ).count()
        
        official.poor_ratings_count = poor_ratings
        
        # Update marked_for_review status
        official.marked_for_review = poor_ratings >= 5
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Feedback deleted successfully',
            'official': {
                'id': official.id,
                'average_rating': official.average_rating,
                'poor_ratings_count': official.poor_ratings_count,
                'marked_for_review': official.marked_for_review
            }
        })
    except Exception as e:
        logger.error(f"Error deleting feedback: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while deleting feedback'}), 500

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Add sentiment_score column if it doesn't exist
        try:
            with db.engine.connect() as conn:
                # Check if column exists
                result = conn.execute("SELECT * FROM pragma_table_info('feedback') WHERE name='sentiment_score'")
                if not result.fetchone():
                    logger.debug("Adding sentiment_score column to feedback table...")
                    conn.execute('ALTER TABLE feedback ADD COLUMN sentiment_score FLOAT')
                    conn.commit()
                    logger.debug("Successfully added sentiment_score column")
        except Exception as e:
            logger.error(f"Error adding sentiment_score column: {str(e)}")
    
    app.run(host='0.0.0.0', port=3000, debug=True)
