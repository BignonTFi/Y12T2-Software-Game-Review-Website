from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hyrule-secret-key-12345' # Required for sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hyrule_archives.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirects here if @login_required is triggered

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Relationship: One user can have many reviews
    reviews = db.relationship('Review', backref='author', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_title = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    # Fetch all reviews to display on the home page
    all_reviews = Review.query.order_by(Review.date_posted.desc()).all()
    return render_template('index.html', reviews=all_reviews)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        
        # Requirement 5: Secure password hashing
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=request.form['username'], password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/add_review', methods=['POST'])
@login_required
def add_review():
    new_review = Review(
        game_title=request.form['game_title'],
        rating=int(request.form['rating']),
        content=request.form['content'],
        user_id=current_user.id
    )
    db.session.add(new_review)
    db.session.commit()
    return redirect(url_for('index'))

# --- DB INITIALIZATION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates the .db file and tables
    app.run(debug=True)