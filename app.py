from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import yfinance as yf
from datetime import datetime
from functools import wraps
import pandas as pd

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:67mustang@localhost/user_log'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", 'your_secret_key_here')

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)

class stock_price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.0)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

    def __repr__(self):
        return f"<Stock {self.symbol}: ${self.price}>"
    
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

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


def get_stock_price(symbol):
    try:
        stock_data = yf.Ticker(symbol)
        hist = stock_data.history(period="1d")
        if not hist.empty:
            price = hist["Close"].iloc[-1] 
            print(f"Fetched price for {symbol}: {price}") 
            return float(price)  
    except Exception as e:
        print(f"Error fetching stock price for {symbol}: {e}")
    return 0.0  


@app.route('/admin_add_remove_stock', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_remove_stock():
    if request.method == 'POST':
        symbol = request.form.get("symbol", "").upper()
        quantity = request.form.get("quantity", 0, type=int)

        if not symbol:
            flash("Please insert stock.")
            return redirect(url_for('admin_add_remove_stock'))

        if quantity <= 0:
            flash("Quantity cannot be 0.")
            return redirect(url_for('admin_add_remove_stock'))

        existing_stock = stock_price.query.filter_by(symbol=symbol).first()
        if existing_stock:
            flash(f"{symbol} is already being tracked.")
            return redirect(url_for('admin_add_remove_stock'))

        price = get_stock_price(symbol)
        if price == 0.0:
            flash(f"Failed to fetch stock price for {symbol}.")
            return redirect(url_for('admin_add_remove_stock'))

        new_stock = stock_price(symbol=symbol, price=price, quantity=quantity)
        db.session.add(new_stock)
        db.session.commit()

        flash(f"Stock {symbol} added successfully with price ${price:.2f} and quantity {quantity}!")
        return redirect(url_for('admin_add_remove_stock'))

    stocks = stock_price.query.all()
    return render_template('admin_add_remove_stock.html', stocks=stocks)

@app.route('/delete_stock/<int:stock_id>', methods=['POST'])
@login_required
@admin_required
def delete_stock(stock_id):
    stock = stock_price.query.get(stock_id)
    if not stock:
        flash("Stock not found.")
        return redirect(url_for('admin_add_remove_stock'))

    db.session.delete(stock)
    db.session.commit()

    flash("Stock deleted.")
    return redirect(url_for('admin_add_remove_stock'))

@app.route('/edit_stock/<int:stock_id>', methods=['POST'])
def edit_stock(stock_id):
    stock = stock_price.query.get(stock_id)
    if stock:
        new_quantity = request.form.get('quantity', type=int)
        if new_quantity and new_quantity > 0:
            stock.quantity = new_quantity
            stock.timestamp = datetime.utcnow() 
            db.session.commit()
            flash(f'Stock {stock.symbol} updated.')
        else:
            flash('Invalid quantity.')
    else:
        flash('Stock not found.')

    return redirect(url_for('admin_add_remove_stock'))

@app.route('/buy_sell_stock')
@login_required
def buy_sell_stock():
    stocks = stock_price.query.order_by(stock_price.timestamp.desc()).limit(10).all()
    return render_template('buy_sell_stock.html', stocks=stocks)

def fetch_stock_prices():
    stock_symbols = [stock.symbol for stock in stock_price.query.all()]
    if not stock_symbols:
        print("No stocks available.")
        return
    try:
        data = yf.download(stock_symbols, period="1d")['Adj Close'].iloc[-1]
        
        for symbol in stock_symbols:
            if not pd.isna(data[symbol]): 
                stock = stock_price.query.filter_by(symbol=symbol).first()
                if stock:
                    stock.price = data[symbol]
                    stock.timestamp = datetime.utcnow()
        
        db.session.commit()
        print("Stock prices updated.")

    except Exception as e:
        print(f"Error fetching stock data: {e}")

@app.route('/') 
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

