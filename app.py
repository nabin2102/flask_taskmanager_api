from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1800 
jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    tasks = db.relationship('Task', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Task('{self.title}', '{self.description}', '{self.completed}')"

with app.app_context():
    db.create_all()

@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })
    return jsonify({'users': output})

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Missing name, email, or password'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'User already exists. Please Log in.'}), 202

    new_user = User(
        public_id=str(uuid.uuid4()),
        name=name,
        email=email,
        password=generate_password_hash(password)
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully.'}), 200

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400

    # Validate the user's credentials
    user = User.query.filter_by(email=auth.get('email')).first()
    if not user or not check_password_hash(user.password, auth.get('password')):
        return jsonify({'message': 'Invalid email or password'}), 401

    # If the credentials are valid, create an access token and return it in the response
    access_token = create_access_token(identity=user.public_id)
    return jsonify({'access_token': access_token}), 200

@app.route('/success', methods=['GET'])
@jwt_required()
def success():
    access_token = get_jwt_identity()
    return jsonify({'message': 'Success', 'access_token': access_token}), 200



@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=current_user_id).all()
    output = []
    for task in tasks:
        output.append({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'completed': task.completed
        })
    return jsonify({'tasks': output})

@app.route('/tasks/<int:task_id>', methods=['GET'])
@jwt_required()
def get_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != get_jwt_identity():
        return jsonify({'message': 'Unauthorized to access this task'}), 403
    return jsonify({
        'id': task.id,
        'title': task.title,
        'description': task.description,
        'completed': task.completed
    })

@app.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    data = request.json
    title = data.get('title')
    description = data.get('description')
    user_id = get_jwt_identity()
    new_task = Task(title=title, description=description, user_id=user_id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created successfully'}), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != get_jwt_identity():
        return jsonify({'message': 'Unauthorized to update this task'}), 403
    data = request.json
    task.title = data.get('title', task.title)
    task.description = data.get('description', task.description)
    task.completed = data.get('completed', task.completed)
    db.session.commit()
    return jsonify({'message': 'Task updated successfully'})

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != get_jwt_identity():
        return jsonify({'message': 'Unauthorized to delete this task'}), 403
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully'})

if __name__ == "__main__":
    app.run(debug=True)
