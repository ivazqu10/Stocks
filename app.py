from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Jaman3240@localhost/user_log'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Ensure this is set

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

# User model with role-based access control
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)

# Initialize database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hashed_password = bcrypt.generate_password_hash(request.form.get("password")).decode('utf-8')
        user = Users(
            username=request.form.get("username"),
            password=hashed_password,
            role="user"  # Default role is "user"
        )
        db.session.add(user)
        db.session.commit()
        print(f"User {user.username} registered successfully.")  # Debug print
        login_user(user)
        return redirect(url_for("user_dashboard"))  # Redirect to user_dashboard after registration
    return render_template("sign_up.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(f"Attempting login with username: {username}")  # Debug print

        # Fetch user from the database based on the entered username
        user = Users.query.filter_by(username=username).first()

        if user:
            print(f"User {user.username} found in the database.")  # Debug print
            if bcrypt.check_password_hash(user.password, password):  # Check if the password is correct
                print(f"Password is correct for {user.username}")  # Debug print
                login_user(user)  # Log the user in
                return redirect(url_for("user_dashboard"))  # Redirect to user dashboard after successful login
            else:
                print(f"Incorrect password for {username}.")  # Debug print
                return render_template("login.html", error="Incorrect password.")  # Optionally show an error message
        else:
            print(f"User {username} not found in the database.")  # Debug print
            return render_template("login.html", error="User not found.")  # Optionally show an error message
    return render_template("login.html")

@app.route('/')
@login_required  # Restricts access to authenticated users only
def user_dashboard():
    print(f"Accessing user_dashboard as {current_user.username}")  # Debug print
    return render_template("user_dashboard.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# User Pages
@app.route('/portfolio')
def portfolio():
    return render_template('portfolio.html')

@app.route('/instructions_page')
def instructions_page():
    return render_template('instructions_page.html')

@app.route('/buy_sell_stock')
def buy_sell_stock():
    return render_template('buy_sell_stock.html')

@app.route('/funds')
def funds():
    return render_template('funds.html')

# Admin Pages
@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin_logs')
def admin_logs():
    return render_template('admin_logs.html')

@app.route('/admin_market_hours')
def admin_market_hours():
    return render_template('admin_market_hours.html')

@app.route('/admin_account_management')
def admin_account_management():
    return render_template('admin_account_management.html')

@app.route('/admin_add_remove_stock')
def admin_add_remove_stock():
    return render_template('admin_add_remove_stock.html')

if __name__ == '__main__':
    app.run(debug=True)
