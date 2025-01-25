from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__, static_folder='.')
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///feedback.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    aadhar_id = db.Column(db.String(12), primary_key=True)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')
    
    def get_id(self):
        return self.aadhar_id

class Official(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    photo_url = db.Column(db.String(200))
    average_rating = db.Column(db.Float, default=0.0)
    feedbacks = db.relationship('Feedback', backref='official', lazy=True)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    official_id = db.Column(db.Integer, db.ForeignKey('official.id'), nullable=False)
    user_aadhar_id = db.Column(db.String(12), db.ForeignKey('user.aadhar_id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(aadhar_id):
    return User.query.get(aadhar_id)

# Routes
@app.route('/')
def serve_login():
    return send_from_directory('.', 'login.html')

@app.route('/search.html')
@login_required
def serve_search():
    return send_from_directory('.', 'search.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.get(data['aadhaarId'])
    
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/officials/search', methods=['GET'])
@login_required
def search_officials():
    query = request.args.get('query', '').lower()
    officials = Official.query.filter(Official.name.ilike(f'%{query}%')).all()
    return jsonify([{
        'id': o.id,
        'name': o.name,
        'position': o.position,
        'photo_url': o.photo_url,
        'rating': o.average_rating
    } for o in officials])

@app.route('/api/feedback/<int:official_id>', methods=['GET'])
@login_required
def get_feedbacks(official_id):
    feedbacks = Feedback.query.filter_by(official_id=official_id)\
        .order_by(Feedback.timestamp.desc())\
        .limit(10)\
        .all()
    
    return jsonify([{
        'id': f.id,
        'user_name': User.query.get(f.user_aadhar_id).name,
        'category': f.category,
        'rating': f.rating,
        'description': f.description,
        'timestamp': f.timestamp.strftime('%Y-%m-%d %H:%M')
    } for f in feedbacks])

@app.route('/api/feedback', methods=['POST'])
@login_required
def submit_feedback():
    data = request.get_json()
    feedback = Feedback(
        official_id=data['officialId'],
        user_aadhar_id=current_user.aadhar_id,
        category=data['category'],
        rating=data['rating'],
        description=data['description']
    )
    db.session.add(feedback)
    
    # Update official's average rating
    official = Official.query.get(data['officialId'])
    db.session.flush()  # Ensure the new feedback is available
    feedbacks = official.feedbacks
    official.average_rating = sum(f.rating for f in feedbacks) / len(feedbacks)
    
    db.session.commit()

    # Return updated feedbacks along with success status
    return jsonify({
        'success': True,
        'feedbacks': [{
            'id': f.id,
            'user_name': User.query.get(f.user_aadhar_id).name,
            'category': f.category,
            'rating': f.rating,
            'description': f.description,
            'timestamp': f.timestamp.strftime('%Y-%m-%d %H:%M')
        } for f in Feedback.query.filter_by(official_id=data['officialId'])
            .order_by(Feedback.timestamp.desc())
            .limit(10)
            .all()]
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
