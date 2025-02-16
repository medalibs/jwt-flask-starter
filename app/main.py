import os
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

# User model with unique email
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hash

# Route for user registration
@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json()
    
    # Check for required fields
    if not data or not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({"msg": "Missing required fields"}), 400

    username = data['username']
    email = data['email']
    password = data['password']

    # Check if email or username already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already exists!"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists!"}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)
    
    # Create the user
    user = User(username=username, email=email, password=hashed_password)
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
    
    if not data or not all(key in data for key in ['username', 'password']):
        return jsonify({"msg": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
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
        return jsonify({"username": user.username, "email": user.email})
    return jsonify({"msg": "User not found!"}), 404

# Create the database and tables within the correct context
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)