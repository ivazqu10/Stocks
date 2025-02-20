from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Madrid0329.@localhost/stocks_db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize database and Bootstrap
db = SQLAlchemy(app)

# User Dashboard
@app.route('/') 
def user_dashboard():
    return render_template('user_dashboard.html')

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
