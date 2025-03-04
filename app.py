from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import yfinance as yf
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:67mustang@localhost/user_log'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", 'your_secret_key_here')

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)

class StockPrice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<Stock {self.symbol}: ${self.price}>"

with app.app_context():
    db.create_all()  

def fetch_stock_prices(stock_symbols):
    stock_objects = []
    for stock in stock_symbols:
        try:
            ticker = yf.Ticker(stock)
            latest_price = ticker.info.get("regularMarketPrice")

            if latest_price is not None:
                stock_objects.append(StockPrice(symbol=stock, price=latest_price))
                print(f"Stored {stock}: ${latest_price:.2f} in database")
            else:
                print(f"No market price available for {stock}")

        except Exception as e:
            print(f"Error fetching {stock}: {e}")

    if stock_objects:
        db.session.bulk_save_objects(stock_objects)
        db.session.commit()

@app.route('/update_stocks')
@login_required
def update_stocks():
    stock_symbols = ["AAPL", "TSLA", "GOOG"]
    fetch_stock_prices(stock_symbols)
    flash("Stock prices updated successfully!", "success")
    return redirect(url_for('buy_sell_stock'))

@app.route('/buy_sell_stock')
@login_required
def buy_sell_stock():
    stocks = StockPrice.query.order_by(StockPrice.timestamp.desc()).limit(10).all()
    return render_template('buy_sell_stock.html', stocks=stocks)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Access Denied!", "danger")
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))

        flash("Invalid username or password!", "danger")
    return render_template('login.html')

@app.route('/') 
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/portfolio') 
@login_required
def portfolio():
    return render_template('portfolio.html') 

@app.route('/instructions_page') 
@login_required
def instructions_page():
    return render_template('instructions_page.html')

@app.route('/funds') 
@login_required
def funds():
    return render_template('funds.html')

@app.route('/admin_dashboard') 
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin_logs') 
@login_required
@admin_required
def admin_logs():
    return render_template('admin_logs.html')

@app.route('/admin_market_hours') 
@login_required
@admin_required
def admin_market_hours():
    return render_template('admin_market_hours.html')

@app.route('/admin_account_management') 
@login_required
@admin_required
def admin_account_management():
    return render_template('admin_account_management.html')

@app.route('/admin_add_remove_stock') 
@login_required
@admin_required
def admin_add_remove_stock():
    return render_template('admin_add_remove_stock.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
