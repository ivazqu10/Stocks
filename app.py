from flask import Flask, render_template, request, url_for, redirect, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import yfinance as yf
from datetime import datetime
from functools import wraps
import pandas as pd
from datetime import datetime
import pytz

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:67mustang@localhost/stocks_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", 'your_secret_key_here')

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock_price.id'), nullable=False)
    shares_owned = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref=db.backref('portfolio', lazy=True))
    stock = db.relationship('stock_price', backref=db.backref('holdings', lazy=True))

class TransactionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock_price.id'), nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # "BUY" or "SELL"
    shares = db.Column(db.Integer, nullable=False)
    price_per_share = db.Column(db.Float, nullable=False)
    total_cost = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('transactions', lazy=True))
    stock = db.relationship('stock_price', backref=db.backref('transactions', lazy=True))

class MarketHours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    open_time = db.Column(db.Time, nullable=False)  # Stored in UTC
    close_time = db.Column(db.Time, nullable=False)  # Stored in UTC

    def is_market_open(self):
        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)  # Current time in UTC
        now_mst = now_utc.astimezone(MST)  # Convert UTC to MST

        # Convert stored time (UTC) to full datetime for conversion
        open_time_mst = datetime.combine(datetime.utcnow(), self.open_time).replace(tzinfo=pytz.utc).astimezone(MST).time()
        close_time_mst = datetime.combine(datetime.utcnow(), self.close_time).replace(tzinfo=pytz.utc).astimezone(MST).time()

        return open_time_mst <= now_mst.time() <= close_time_mst

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
            flash("Please insert stock.", "danger")
            return redirect(url_for('admin_add_remove_stock'))

        if quantity <= 0:
            flash("Quantity cannot be 0.", "danger")
            return redirect(url_for('admin_add_remove_stock'))

        existing_stock = stock_price.query.filter_by(symbol=symbol).first()
        if existing_stock:
            flash(f"{symbol} is already being tracked.", "warning")
            return redirect(url_for('admin_add_remove_stock'))

        price = get_stock_price(symbol)
        if price == 0.0:
            flash(f"Failed to fetch stock price for {symbol}.", "danger")
            return redirect(url_for('admin_add_remove_stock'))

        new_stock = stock_price(symbol=symbol, price=price, quantity=quantity)
        db.session.add(new_stock)
        db.session.commit()

        # Flash message only for admins
        flash(f"Stock {symbol} added successfully with price ${price:.2f} and quantity {quantity}!", "admin")

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
    db.session.expire_all()  # Forces Flask to get fresh database data
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

        
        price_adjustment = random.uniform(-5, 5)
        new_price = max(price + price_adjustment, 0.01)  

        total_sale_value = new_price * shares
        user_portfolio.shares_owned -= shares
        user.cash_balance += total_sale_value
        stock.quantity += shares

        transaction = TransactionHistory(
            user_id=user.id,
            stock_id=stock.id,
            transaction_type="SELL",
            shares=shares,
            price_per_share=new_price,
            total_cost=total_sale_value
        )
        db.session.add(transaction)

        flash(f"Sold at adjusted price: ${new_price:.2f}", "info")

    db.session.commit()
    flash(f"Transaction completed! Your new balance is ${user.cash_balance:.2f}.", "success")
    return redirect(url_for("buy_sell_stock"))

@app.route("/trade_confirmation", methods=["POST"])
@login_required
def trade_confirmation():
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
    new_balance = user.cash_balance

    if action == "buy":
        if new_balance < total_cost:
            flash("Insufficient funds for this trade.", "danger")
            return redirect(url_for("buy_sell_stock"))
        new_balance -= total_cost

    elif action == "sell":
        stock = UserPortfolio.query.filter_by(user_id=user.id, stock_id=stock_price.query.filter_by(symbol=symbol).first().id).first()
        if not stock or stock.shares_owned < shares:
            flash("Not enough shares to sell.", "danger")
            return redirect(url_for("buy_sell_stock"))
        new_balance += total_cost

    return render_template("trade_confirmation.html", symbol=symbol, action=action, shares=shares, price=price, total_cost=total_cost, new_balance=new_balance)


@app.route("/execute_trade", methods=["POST"])
@login_required
def execute_trade():
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


@app.route("/funds_confirmation", methods=["POST"])
@login_required
def funds_confirmation():
    action = request.form.get("action")  # "deposit" or "withdraw"
    amount = request.form.get("amount", type=float)

    if not action or not amount or amount <= 0:
        flash("Invalid transaction request.", "danger")
        return redirect(url_for("funds"))

    # Prevent overdrafting if withdrawing
    if action == "withdraw" and current_user.cash_balance < amount:
        flash("Insufficient funds for withdrawal.", "danger")
        return redirect(url_for("funds"))

    return render_template("funds_confirmation.html", action=action, amount=f"{amount:,.2f}")

@app.route("/process_funds", methods=["POST"])
@login_required
def process_funds():
    action = request.form.get("action")
    amount = request.form.get("amount")

    print(f"DEBUG: Raw Data - action={action}, amount={amount}")  # Debugging Step 1

    # Remove commas before converting to float
    if amount:
        amount = amount.replace(",", "")  # ✅ Remove commas from number

    try:
        amount = float(amount)  # Convert to float safely
    except (ValueError, TypeError):
        flash("Invalid amount entered.", "danger")
        return redirect(url_for("funds"))

    print(f"DEBUG: Converted Data - action={action}, amount={amount}")  # Debugging Step 2

    if not action or amount <= 0:
        flash("Invalid transaction request.", "danger")
        return redirect(url_for("funds"))

    print(f"DEBUG: Before Commit - Balance: {current_user.cash_balance}")

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
    print(f"DEBUG: After Commit - Balance: {current_user.cash_balance}")  # Debugging Step 3

    return redirect(url_for("funds"))

@app.route("/transactions")
@login_required
def transactions():
    transactions = TransactionHistory.query.filter_by(user_id=current_user.id).order_by(TransactionHistory.timestamp.desc()).all()
    return render_template("transactions.html", transactions=transactions)

@app.route('/portfolio')
@login_required
def portfolio():
    return render_template('portfolio.html')

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
    # Query all transactions from the TransactionHistory table
    transactions = TransactionHistory.query.order_by(TransactionHistory.timestamp.desc()).all()
    
    return render_template('admin_logs.html', transactions=transactions)

# Function and Route so the Adminstrator can Edit market Hours!
MST = pytz.timezone("America/Phoenix")

@app.route("/admin/market_hours", methods=["GET", "POST"])
@login_required
@admin_required
def admin_market_hours():
    market_hours = MarketHours.query.first()

    if request.method == "POST":
        open_time_mst = request.form.get("open_time")
        close_time_mst = request.form.get("close_time")

        if not open_time_mst or not close_time_mst:
            flash("Please enter valid market hours.", "danger")
            return redirect(url_for("admin_market_hours"))

        # Convert input time from string to datetime in MST
        open_time_dt_mst = datetime.strptime(open_time_mst, "%H:%M")
        close_time_dt_mst = datetime.strptime(close_time_mst, "%H:%M")

        # Ensure the datetime is localized to MST before converting to UTC
        open_time_dt_mst = MST.localize(datetime.combine(datetime.today(), open_time_dt_mst.time()))
        close_time_dt_mst = MST.localize(datetime.combine(datetime.today(), close_time_dt_mst.time()))

        # Convert MST to UTC and store only the time part
        open_time_utc = open_time_dt_mst.astimezone(pytz.utc).time()
        close_time_utc = close_time_dt_mst.astimezone(pytz.utc).time()

        # Store in the database
        if market_hours:
            market_hours.open_time = open_time_utc
            market_hours.close_time = close_time_utc
        else:
            market_hours = MarketHours(open_time=open_time_utc, close_time=close_time_utc)
            db.session.add(market_hours)

        db.session.commit()
        flash("Market hours updated successfully!", "success")
        return redirect(url_for("admin_market_hours"))

    # Convert stored UTC times back to MST for display
    open_time_mst = None
    close_time_mst = None

    if market_hours:
        open_time_dt_utc = datetime.combine(datetime.today(), market_hours.open_time).replace(tzinfo=pytz.utc)
        close_time_dt_utc = datetime.combine(datetime.today(), market_hours.close_time).replace(tzinfo=pytz.utc)

        open_time_mst = open_time_dt_utc.astimezone(MST).strftime('%H:%M')
        close_time_mst = close_time_dt_utc.astimezone(MST).strftime('%H:%M')

    return render_template("admin_market_hours.html", open_time=open_time_mst, close_time=close_time_mst)

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
