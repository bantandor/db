from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    age = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create the database
with app.app_context():
    db.create_all()

# Route to handle registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=hashed_password, first_name='', last_name='', age='')
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Route to handle login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# Route to handle logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route to handle the main page
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        age = request.form['age']
        
        # Create a new user and add to the database
        new_user = User(first_name=first_name, last_name=last_name, age=age, username=f'user_{first_name}_{last_name}', password='default_password', added_by=current_user.id)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('New user added successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to add user. Username must be unique.', 'danger')
        return redirect(url_for('home'))
    
    users = User.query.filter_by(added_by=current_user.id).all()
    return render_template('index.html', users=users)

# Route to handle the editing of user data
@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit(user_id):
    user = User.query.filter_by(id=user_id, added_by=current_user.id).first_or_404()
    
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.age = request.form['age']
        
        db.session.commit()
        flash('User details updated successfully.', 'success')
        return redirect(url_for('home'))
    
    return render_template('edit.html', user=user)

# Route to handle deleting a user
@app.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete(user_id):
    user = User.query.filter_by(id=user_id, added_by=current_user.id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
