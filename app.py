from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import yfinance as yf
from datetime import datetime
from functools import wraps
import pandas as pd
from datetime import datetime, time, date, timedelta
import pytz
import random
from sqlalchemy.ext.hybrid import hybrid_property
import json
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:Jaman3240%23@my-rds-instance.ce92g2g4cjab.us-east-1.rds.amazonaws.com:3306/stocks_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", 'your_secret_key_here')

db = SQLAlchemy(app)
# Classes are our Tables in DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)
    cash_balance = db.Column(db.Float, default=0.0) 

class stock_price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.0)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class UserPortfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock_price.id'), nullable=False)
    shares_owned = db.Column(db.Integer, default=0)
    last_sell_price = db.Column(db.Float, default=0.0)
    user = db.relationship('User', backref=db.backref('portfolio', lazy=True, passive_deletes=True))
    stock = db.relationship('stock_price', backref=db.backref('holdings', lazy=True))

class TransactionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock_price.id'), nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False) 
    shares = db.Column(db.Integer, nullable=False)
    price_per_share = db.Column(db.Float, nullable=False)
    total_cost = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('transactions', lazy=True, passive_deletes=True))
    stock = db.relationship('stock_price', backref=db.backref('transactions', lazy=True))

class MarketHours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    open_time = db.Column(db.Time, nullable=False)
    close_time = db.Column(db.Time, nullable=False)
    _closed_days = db.Column("closed_days", db.Text, nullable=True)

    @hybrid_property
    def closed_days(self):
        raw = self._closed_days
        return json.loads(raw) if raw else []

    @closed_days.setter
    def closed_days(self, value):
        if not isinstance(value, list):
            raise ValueError("closed_days must be a list of date strings.")
        self._closed_days = json.dumps(value)

    def is_market_open(self):
        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
        now_mst = now_utc.astimezone(MST)
        today_str = now_mst.strftime('%Y-%m-%d')

        if today_str in self.closed_days:
            return False

        open_time_mst = datetime.combine(datetime.utcnow(), self.open_time).replace(tzinfo=pytz.utc).astimezone(MST).time()
        close_time_mst = datetime.combine(datetime.utcnow(), self.close_time).replace(tzinfo=pytz.utc).astimezone(MST).time()

        return open_time_mst <= now_mst.time() <= close_time_mst

    def add_closed_day(self, date_str):
        updated = list(self.closed_days)
        if date_str not in updated:
            updated.append(date_str)
            self.closed_days = updated

    def remove_closed_day(self, date_str):
        updated = list(self.closed_days)
        if date_str in updated:
            updated.remove(date_str)
            self.closed_days = updated

    def clear_closed_days(self):
        self.closed_days = []

    def __repr__(self):
        return f"<MarketHours Open: {self.open_time} Close: {self.close_time} Closed Days: {self.closed_days}>"

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    username = db.Column(db.String(150))
    action = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('logs', lazy=True, passive_deletes=True))

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
        price_mode = request.form.get("price_mode")  # 'manual' or 'live'
        manual_price = request.form.get("manual_price", type=float)

        if not symbol:
            flash("Please insert stock.", "danger")
            return redirect(url_for('admin_add_remove_stock'))

        if quantity <= 0:
            flash("Quantity must be greater than 0.", "danger")
            return redirect(url_for('admin_add_remove_stock'))

        existing_stock = stock_price.query.filter_by(symbol=symbol).first()
        if existing_stock:
            flash(f"{symbol} is already being tracked.", "warning")
            return redirect(url_for('admin_add_remove_stock'))

        if price_mode == "manual":
            if not manual_price or manual_price <= 0:
                flash("Manual price must be greater than 0.", "danger")
                return redirect(url_for('admin_add_remove_stock'))
            price = manual_price
        else:
            try:
                price = get_stock_price(symbol)
            except Exception as e:
                flash(f"Error fetching price: {str(e)}", "danger")
                return redirect(url_for('admin_add_remove_stock'))

            if price == 0.0:
                flash(f"Failed to fetch stock price for {symbol}.", "danger")
                return redirect(url_for('admin_add_remove_stock'))

        new_stock = stock_price(symbol=symbol, price=price, quantity=quantity)
        db.session.add(new_stock)
        db.session.commit()

        flash(f"Stock {symbol} added successfully with price ${price:.2f} and quantity {quantity}!", "success")
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

@app.route("/buy_sell_stock")
@login_required
def buy_sell_stock():
    stocks = stock_price.query.all()
    db.session.expire_all()  
    market_hours = MarketHours.query.first()

    market_open = market_hours.is_market_open() if market_hours else False

    return render_template("buy_sell_stock.html", stocks=stocks, market_open=market_open)

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
        email = request.form.get('email')
        password = generate_password_hash(request.form['password'])

        if not email:
            flash("Email is required!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            db.session.add(Log(user_id=user.id, username=user.username, action="login"))
            db.session.commit()
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            log_entry = Log(
                user_id=user.id if user else None,
                username=username,
                action="failed_login"
            )
            db.session.add(log_entry)
            db.session.commit()
            flash("Invalid username or password!", "danger")
            
    return render_template('login.html')

def get_adjusted_price(original_price):
    price_adjustment = random.uniform(-5, 5)
    return max(original_price + price_adjustment, 0.01)  

@app.route("/trade_stock", methods=["POST"])
@login_required
def trade_stock():
    symbol = request.form.get("symbol")
    action = request.form.get("action")
    shares = request.form.get("shares")
    price = request.form.get("price")

    if not symbol or not action or not shares or not price:
        flash("Invalid trade request.", "danger")
        return redirect(url_for("buy_sell_stock"))

    shares = int(shares)
    price = float(price)

    user = current_user
    stock = stock_price.query.filter_by(symbol=symbol).first()

    if not stock:
        flash("Stock not found.", "danger")
        return redirect(url_for("buy_sell_stock"))

    user_portfolio = UserPortfolio.query.filter_by(user_id=user.id, stock_id=stock.id).first()

    if action == "buy":
        total_cost = price * shares

        if stock.quantity < shares:
            flash(f"Not enough shares available! Only {stock.quantity} left.", "danger")
            return redirect(url_for("buy_sell_stock"))

        if user.cash_balance < total_cost:
            flash("Insufficient funds.", "danger")
            return redirect(url_for("buy_sell_stock"))

        user.cash_balance -= total_cost
        stock.quantity -= shares

        if user_portfolio:
            user_portfolio.shares_owned += shares
        else:
            new_entry = UserPortfolio(user_id=user.id, stock_id=stock.id, shares_owned=shares)
            db.session.add(new_entry)

        transaction = TransactionHistory(
            user_id=user.id,
            stock_id=stock.id,
            transaction_type="BUY",
            shares=shares,
            price_per_share=price,
            total_cost=total_cost
        )
        db.session.add(transaction)

    elif action == "sell":
        if not user_portfolio or user_portfolio.shares_owned < shares:
            flash("Not enough shares to sell.", "danger")
            return redirect(url_for("buy_sell_stock"))

        adjusted_price = get_adjusted_price(price)  

        total_sale_value = adjusted_price * shares
        user_portfolio.shares_owned -= shares
        user.cash_balance += total_sale_value
        stock.quantity += shares

        user_portfolio.last_sell_price = adjusted_price

        transaction = TransactionHistory(
            user_id=user.id,
            stock_id=stock.id,
            transaction_type="SELL",
            shares=shares,
            price_per_share=adjusted_price,
            total_cost=total_sale_value
        )
        db.session.add(transaction)

        flash(f"Sold at adjusted price: ${adjusted_price:.2f}", "info")

    db.session.commit()
    flash(f"Transaction completed! Your new balance is ${user.cash_balance:.2f}.")
    return redirect(url_for("buy_sell_stock"))

@app.route("/refresh_prices", methods=["POST"])
@login_required
def refresh_prices():
    user = current_user
    portfolios = UserPortfolio.query.filter_by(user_id=user.id).all()

    for portfolio in portfolios:
        if portfolio.shares_owned > 0:
            portfolio.last_sell_price = get_adjusted_price(portfolio.stock.price) 

    db.session.commit()
    return redirect(url_for("portfolio"))


@app.route("/trade_confirmation", methods=["POST"])
@login_required
def trade_confirmation():
    print(f"Received Trade Request: {request.form}") 

    symbol = request.form.get("symbol")
    action = request.form.get("action")
    shares = request.form.get("shares")
    price = request.form.get("price")

    if not symbol or not action or not shares or not price:
        flash("Invalid trade request.", "danger")
        return redirect(url_for("buy_sell_stock"))

    shares = int(shares)
    price = float(price)
    total_cost = shares * price

    user = current_user
    stock = stock_price.query.filter_by(symbol=symbol).first()

    if not stock:
        flash("Stock not found.", "danger")
        return redirect(url_for("buy_sell_stock"))

    if action == "buy":
        if stock.quantity < shares:
            flash(f"Not enough shares available! Only {stock.quantity} left.", "danger")
            return redirect(url_for("buy_sell_stock"))

        if user.cash_balance < total_cost:
            flash("Insufficient funds.", "danger")
            return redirect(url_for("buy_sell_stock"))

        new_balance = user.cash_balance - total_cost

    elif action == "sell":
        user_portfolio = UserPortfolio.query.filter_by(user_id=user.id, stock_id=stock.id).first()
        if not user_portfolio or user_portfolio.shares_owned < shares:
            flash("Not enough shares to sell.", "danger")
            return redirect(url_for("buy_sell_stock"))

        new_balance = user.cash_balance + total_cost

    return render_template("trade_confirmation.html", symbol=symbol, action=action, shares=shares, price=price, total_cost=total_cost, new_balance=new_balance)

@app.route("/execute_trade", methods=["POST"])
@login_required
def execute_trade():
    print(f"Executing Trade: {request.form}")

    symbol = request.form.get("symbol")
    action = request.form.get("action")
    shares = int(request.form.get("shares"))
    price = float(request.form.get("price"))
    total_cost = float(request.form.get("total_cost"))

    user = current_user
    stock = stock_price.query.filter_by(symbol=symbol).first()

    if not stock:
        flash("Stock not found.", "danger")
        return redirect(url_for("buy_sell_stock"))

    user_portfolio = UserPortfolio.query.filter_by(user_id=user.id, stock_id=stock.id).first()

    if action == "buy":
        if stock.quantity < shares:
            flash(f"Not enough shares available! Only {stock.quantity} left.", "danger")
            return redirect(url_for("buy_sell_stock"))

        if user.cash_balance < total_cost:
            flash("Insufficient funds.", "danger")
            return redirect(url_for("buy_sell_stock"))

        user.cash_balance -= total_cost
        stock.quantity -= shares

        if user_portfolio:
            user_portfolio.shares_owned += shares
        else:
            new_entry = UserPortfolio(user_id=user.id, stock_id=stock.id, shares_owned=shares)
            db.session.add(new_entry)

        transaction = TransactionHistory(
            user_id=user.id,
            stock_id=stock.id,
            transaction_type="BUY",
            shares=shares,
            price_per_share=price,
            total_cost=total_cost
        )
        db.session.add(transaction)

    elif action == "sell":
        if not user_portfolio or user_portfolio.shares_owned < shares:
            flash("Not enough shares to sell.", "danger")
            return redirect(url_for("buy_sell_stock"))

        total_sale_value = price * shares
        user_portfolio.shares_owned -= shares
        user.cash_balance += total_sale_value
        stock.quantity += shares

        transaction = TransactionHistory(
            user_id=user.id,
            stock_id=stock.id,
            transaction_type="SELL",
            shares=shares,
            price_per_share=price,
            total_cost=total_sale_value
        )
        db.session.add(transaction)

    db.session.commit() 

    flash(f"Transaction completed! Your new balance is ${user.cash_balance:.2f}.", "success")
    return redirect(url_for("buy_sell_stock"))

# Deposit" or Withdraw funds 
@app.route("/funds_confirmation", methods=["POST"])
@login_required
def funds_confirmation():
    action = request.form.get("action")
    amount = request.form.get("amount")

    try:
        amount = float(amount.replace(",", ""))  
    except (ValueError, TypeError):
        flash("Invalid amount entered.", "danger")
        return redirect(url_for("funds"))

    if not action or amount <= 0:
        flash("Invalid transaction request.", "danger")
        return redirect(url_for("funds"))

    # Calculate new balance before confirming the transaction
    if action == "deposit":
        new_balance = current_user.cash_balance + amount
    elif action == "withdraw":
        if current_user.cash_balance < amount:
            flash("Insufficient funds for withdrawal.", "danger")
            return redirect(url_for("funds"))
        new_balance = current_user.cash_balance - amount

    return render_template("funds_confirmation.html", 
                           action=action, 
                           amount=f"{amount:,.2f}", 
                           new_balance=f"{new_balance:,.2f}")

@app.route("/process_funds", methods=["POST"])
@login_required
def process_funds():
    action = request.form.get("action")
    amount = request.form.get("amount")
    if amount:
        amount = amount.replace(",", "")  

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        flash("Invalid amount entered.", "danger")
        return redirect(url_for("funds"))

    if not action or amount <= 0:
        flash("Invalid transaction request.", "danger")
        return redirect(url_for("funds"))

    if action == "deposit":
        current_user.cash_balance += amount
        db.session.add(current_user)
        flash(f"Successfully deposited ${amount:,.2f}.", "success")

    elif action == "withdraw":
        if current_user.cash_balance >= amount:
            current_user.cash_balance -= amount
            db.session.add(current_user)
            flash(f"Successfully withdrew ${amount:,.2f}.", "success")
        else:
            flash("Insufficient funds.", "danger")
            return redirect(url_for("funds"))

    db.session.commit()

    return redirect(url_for("funds"))

@app.route("/transactions")
@login_required
def transactions():
    transactions = TransactionHistory.query.filter_by(user_id=current_user.id).order_by(TransactionHistory.timestamp.desc()).all()
    return render_template("transactions.html", transactions=transactions)

@app.route('/portfolio')
@login_required
def portfolio():
    user = current_user
    portfolios = UserPortfolio.query.filter_by(user_id=user.id).all()

    total_stock_value = 0
    for stock in portfolios:
        sell_price = stock.last_sell_price if stock.last_sell_price > 0 else stock.stock.price
        total_stock_value += stock.shares_owned * sell_price

    return render_template('portfolio.html', total_stock_value=total_stock_value)

@app.route('/instructions_page') 
@login_required
def instructions_page():
    return render_template('instructions_page.html')

@app.route("/funds")
@login_required
def funds():
    formatted_balance = f"{current_user.cash_balance:,.2f}"  
    return render_template("funds.html", cash_balance=formatted_balance)

@app.route('/admin_dashboard') 
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin_logs') 
@login_required
@admin_required
def admin_logs():
    transactions = TransactionHistory.query.order_by(TransactionHistory.timestamp.desc()).all()
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('admin_logs.html', transactions=transactions, logs=logs)

# Function and Route so the Adminstrator can Edit market Hours!
MST = pytz.timezone("America/Phoenix")
@app.route("/admin/market_hours", methods=["GET", "POST"])
@login_required
@admin_required
def admin_market_hours():
    market_hours = MarketHours.query.first()

    if request.method == "POST":
        # Get time inputs first
        open_time_mst = request.form.get("open_time")
        close_time_mst = request.form.get("close_time")

        if not open_time_mst or not close_time_mst:
            flash("Please enter valid market hours.", "danger")
            return redirect(url_for("admin_market_hours"))

        # Convert to UTC
        open_time_dt_mst = MST.localize(datetime.combine(datetime.today(), datetime.strptime(open_time_mst, "%H:%M").time()))
        close_time_dt_mst = MST.localize(datetime.combine(datetime.today(), datetime.strptime(close_time_mst, "%H:%M").time()))

        open_time_utc = open_time_dt_mst.astimezone(pytz.utc).time()
        close_time_utc = close_time_dt_mst.astimezone(pytz.utc).time()

        # Get closed days input
        closed_days_raw = request.form.get("closed_days")
        closed_days_list = [line.strip() for line in closed_days_raw.splitlines() if line.strip()]

        try:
            valid_dates = validate_closed_dates(closed_days_list)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("admin_market_hours"))

        # Store in the database
        if market_hours:
            market_hours.open_time = open_time_utc
            market_hours.close_time = close_time_utc
            market_hours.closed_days = valid_dates
        else:
            market_hours = MarketHours(
                open_time=open_time_utc,
                close_time=close_time_utc
            )
            market_hours.closed_days = valid_dates
            db.session.add(market_hours)

        db.session.commit()
        flash("Market hours and closed days updated successfully!", "success")
        return redirect(url_for("admin_market_hours"))

    # --- GET Method (Display Preparation) ---

    open_time_mst = close_time_mst = closed_days_text = ""
    holidays = get_us_market_holidays(datetime.now().year)
    custom_closed_days = []

    if market_hours:

        open_time_dt_utc = datetime.combine(datetime.today(), market_hours.open_time).replace(tzinfo=pytz.utc)
        close_time_dt_utc = datetime.combine(datetime.today(), market_hours.close_time).replace(tzinfo=pytz.utc)

        open_time_mst = open_time_dt_utc.astimezone(MST).strftime('%H:%M')
        close_time_mst = close_time_dt_utc.astimezone(MST).strftime('%H:%M')

        custom_closed_days = [d for d in market_hours.closed_days if d not in holidays]

        
        closed_days_text = "\n".join(custom_closed_days)

    return render_template("admin_market_hours.html",
                           open_time=open_time_mst,
                           close_time=close_time_mst,
                           closed_days_text=closed_days_text,
                           holidays=sorted(holidays),
                           custom_closed_days=sorted(custom_closed_days))



def get_us_market_holidays(year):
    holidays = set()

    # New Year’s Day - January 1
    nyd = date(year, 1, 1)
    holidays.add(nyd.strftime("%Y-%m-%d"))

    # Martin Luther King Jr. Day - January 20 (Fixed)
    mlk_day = date(year, 1, 20)
    holidays.add(mlk_day.strftime("%Y-%m-%d"))

    # Washington's Birthday (Presidents Day) - February 17 (fixed)
    presidents_day = date(year, 2, 17)
    holidays.add(presidents_day.strftime("%Y-%m-%d"))

    # Memorial Day - May 26 (fixed)
    memorial_day = date(year, 5, 26)
    holidays.add(memorial_day.strftime("%Y-%m-%d"))

    # Juneteenth - June 19
    juneteenth = date(year, 6, 19)
    holidays.add(juneteenth.strftime("%Y-%m-%d"))

    # Independence Day - July 4
    july4 = date(year, 7, 4)
    holidays.add(july4.strftime("%Y-%m-%d"))

    # Labor Day - September 1
    labor_day = date(year, 9, 1)
    holidays.add(labor_day.strftime("%Y-%m-%d"))

    # Columbus Day - October 13
    columbus_day = date(year, 10, 13)
    holidays.add(columbus_day.strftime("%Y-%m-%d"))

    # Veterans Day - November 11
    veterans_day = date(year, 11, 11)
    holidays.add(veterans_day.strftime("%Y-%m-%d"))

    # Thanksgiving Day - November 27
    thanksgiving = date(year, 11, 27)
    holidays.add(thanksgiving.strftime("%Y-%m-%d"))

    # Christmas Day - December 25
    xmas = date(year, 12, 25)
    holidays.add(xmas.strftime("%Y-%m-%d"))

    return holidays


def validate_closed_dates(date_list):
    valid = []
    today = datetime.now().date()

    for date_str in date_list:
        try:
            dt = datetime.strptime(date_str.strip(), "%Y-%m-%d").date()
            if dt < today:
                continue
            valid.append(dt.strftime("%Y-%m-%d"))
        except ValueError:
            raise ValueError(f"Invalid date format detected: '{date_str}'. Use YYYY-MM-DD.")

    return sorted(set(valid))


@app.template_filter('pretty_date')
def pretty_date(date_str):
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.strftime("%B %d, %Y (%A)")
    except Exception:
        return date_str

@app.route('/admin_account_management') 
@login_required
@admin_required
def admin_account_management():
    users = User.query.all()
    return render_template('admin_account_management.html', users=users)

@app.route('/view_transactions/<int:id>', methods=['GET'])
@login_required
@admin_required
def view_transactions(id):
    user = User.query.get_or_404(id)
    transactions = user.transactions
    return render_template('view_transactions.html', user=user, transactions=transactions)


@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        flash("User updated successfully!", "success")
        return redirect(url_for('admin_account_management'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} has been deleted successfully!", "success")
        return redirect(url_for('admin_account_management'))
    return render_template('delete_user.html', user=user)

@app.route('/delete_user_confirmation/<int:id>', methods=['GET'])
@login_required
@admin_required
def delete_user_confirmation(id):
    user = User.query.get_or_404(id)
    return render_template('delete_user_confirmation.html', user=user)

@app.route('/logout')
@login_required
def logout():
    db.session.add(Log(user_id=current_user.id, username=current_user.username, action="logout"))
    db.session.commit()
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
