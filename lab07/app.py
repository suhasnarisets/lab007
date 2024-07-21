from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        
        if len(password) < 8:
            flash('password did not match criteria')
            return redirect(url_for('signup'))

        if not any(c.islower() for c in password):
            flash('password did not match criteria')
            return redirect(url_for('signup'))
        if not any(c.isupper() for c in password):
            flash('password did not match criteria')
            return redirect(url_for('signup'))
        
        if not password[-1].isdigit():
            flash('password did not match criteria')
            return redirect(url_for('signup'))
        

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already in use')
            return redirect(url_for('signup'))

        new_user = User(first_name=first_name, last_name=last_name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!')
        return redirect(url_for('thankyou'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            return redirect(url_for('secret_page'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/secret')
def secret_page():
    return render_template('secretpage.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)