import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

# Flask and PostgreSQL configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}@{os.environ['DB_HOST']}:{os.environ['DB_PORT']}/{os.environ['DB_NAME']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['FLASK_ENV'] = 'development'
app.config['DEBUG'] = True

CORS(app)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# User model with email as the primary identifier
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hash
    first_name = db.Column(db.String(80), nullable=True)  # Optional field
    last_name = db.Column(db.String(80), nullable=True)   # Optional field
    date_of_birth = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# Route for user registration
@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json()
    
    # Check for required fields
    required_fields = ['email', 'password', 'date_of_birth']
    if not data or not all(key in data for key in required_fields):
        return jsonify({"msg": "Missing required fields"}), 400

    email = data['email']
    password = data['password']
    date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d')  # Assuming date format is YYYY-MM-DD

    # Optional fields
    first_name = data.get('first_name')  # Use .get() to avoid KeyError if field is missing
    last_name = data.get('last_name')    # Use .get() to avoid KeyError if field is missing

    # Check if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already exists!"}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)
    
    # Create the user
    user = User(
        email=email,
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        date_of_birth=date_of_birth
    )
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "An error occurred while registering the user."}), 500

    return jsonify({"msg": "User registered successfully!"}), 201

# Route to obtain a JWT token
@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json()
    
    if not data or not all(key in data for key in ['email', 'password']):
        return jsonify({"msg": "Missing email or password"}), 400

    email = data['email']
    password = data['password']

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # Convert ID to string for JWT identity
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Invalid credentials!"}), 401

# Route to get user information
@app.route('/user_info', methods=['GET', 'OPTIONS'])
@jwt_required()
def user_info():
    if request.method == 'OPTIONS':
        return '', 204
    
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    
    if user:
        return jsonify({
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "date_of_birth": user.date_of_birth.strftime('%Y-%m-%d'),
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
            "is_active": user.is_active
        })
    return jsonify({"msg": "User not found!"}), 404

# Route to update user information
@app.route('/update_user', methods=['PUT', 'OPTIONS'])
@jwt_required()
def update_user():
    if request.method == 'OPTIONS':
        return '', 204
    
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    
    if not user:
        return jsonify({"msg": "User not found!"}), 404

    data = request.get_json()
    
    # Check if data is provided
    if not data:
        return jsonify({"msg": "No data provided to update"}), 400

    # Update fields if they are provided in the request
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'date_of_birth' in data:
        user.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d')
    if 'is_active' in data:
        user.is_active = data['is_active']

    try:
        db.session.commit()
        return jsonify({"msg": "User updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "An error occurred while updating the user."}), 500

# Create the database and tables within the correct context
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)