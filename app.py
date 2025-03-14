from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import jwt
import functools

# Initialize Flask application
app = Flask(__name__)
# Check for required environment variables
required_env_vars = ['DB_USERNAME', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME']
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]

if missing_vars:
    print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
    print("Please set the following environment variables:")
    print("  - DB_USERNAME: RDS database username")
    print("  - DB_PASSWORD: RDS database password")
    print("  - DB_HOST: RDS hostname or endpoint")
    print("  - DB_NAME: Database name")
    exit(1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing')
# Configure database connection using RDS credentials from environment variables
db_username = os.environ.get('DB_USERNAME')
db_password = os.environ.get('DB_PASSWORD')
db_host = os.environ.get('DB_HOST')
db_name = os.environ.get('DB_NAME')

# Create RDS connection string
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_username}:{db_password}@{db_host}:3306/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_EXPIRATION_DELTA'] = 24 * 60 * 60  # 24 hours in seconds

# Enable CORS for all routes to allow requests from S3 static website
CORS(app)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    resources = db.relationship('Resource', backref='owner', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_token(self):
        payload = {
            'user_id': self.id,
            'username': self.username,
            'exp': datetime.utcnow() + timedelta(seconds=app.config['JWT_EXPIRATION_DELTA'])
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return token
    
    def __repr__(self):
        return f'<User {self.username}>'

# Resource Model
class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # e.g., 'rds', 'ec2', etc.
    identifier = db.Column(db.String(100), nullable=False)   # e.g., DB identifier for RDS
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'resource_type': self.resource_type,
            'identifier': self.identifier,
            'created_at': self.created_at.isoformat(),
            'user_id': self.user_id
        }
    
    def __repr__(self):
        return f'<Resource {self.name} ({self.resource_type})>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# JWT Token Authentication Decorator
def token_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated_function

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields!'}), 400
    
    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists!'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered!'}), 400
    
    # Create new user
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password!'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid username or password!'}), 401
    
    # Generate token
    token = user.generate_token()
    
    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }
    }), 200

@app.route('/api/resources', methods=['GET'])
@token_required
def get_resources(current_user):
    resources = Resource.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'resources': [resource.to_dict() for resource in resources]
    }), 200

@app.route('/api/resources', methods=['POST'])
@token_required
def create_resource(current_user):
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('resource_type') or not data.get('identifier'):
        return jsonify({'message': 'Missing required fields!'}), 400
    
    # Create resource record
    new_resource = Resource(
        name=data['name'],
        resource_type=data['resource_type'],
        identifier=data['identifier'],
        user_id=current_user.id
    )
    
    db.session.add(new_resource)
    db.session.commit()
    
    # Example: for RDS resources, you'd call AWS API here
    # This is where you'd integrate with your create-delete-rds.py logic
    
    return jsonify({
        'message': 'Resource created successfully!',
        'resource': new_resource.to_dict()
    }), 201

@app.route('/api/resources/<int:resource_id>', methods=['DELETE'])
@token_required
def delete_resource(current_user, resource_id):
    resource = Resource.query.get_or_404(resource_id)
    
    # Ensure resource belongs to current user
    if resource.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized access to this resource!'}), 403
    
    # Delete resource from database
    db.session.delete(resource)
    db.session.commit()
    
    # Example: for RDS resources, you'd call AWS API here
    # This is where you'd integrate with your create-delete-rds.py logic
    
    return jsonify({'message': 'Resource deleted successfully!'}), 200

@app.route('/api/user', methods=['GET'])
@token_required
def get_user_profile(current_user):
    return jsonify({
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email
        }
    }), 200

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()  # Create tables if they don't exist
            print("Successfully connected to RDS database and created tables if needed")
        except Exception as e:
            print(f"Error connecting to database: {e}")
            exit(1)
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

