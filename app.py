import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user's stock holdings and available cash
    user_id = session["user_id"]
    stocks = db.execute("""
        SELECT symbol, SUM(shares) AS total_shares
        FROM transactions
        WHERE user_id = :user_id
        GROUP BY symbol
        HAVING total_shares > 0""",
                        user_id=user_id)

    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"]

    # Initializing total values here
    total_value = cash
    grand_total = cash

    # Processing each stock
    for stock in stocks:
        quote = lookup(stock["symbol"])

        # If lookup fails or doesn't return required fields
        if quote is None or "price" not in quote or "name" not in quote:
            stock["name"] = "Unknown"
            stock["price"] = 0
            stock["value"] = 0
        # If lookup succeeds
        else:
            stock.update({
                "name": quote["name"],
                "price": quote["price"],
                "value": quote["price"] * stock["total_shares"]
            })
            total_value += stock["value"]
            grand_total += stock["value"]

    return render_template("index.html", stocks=stocks, cash=cash, total_value=total_value, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Retrieve form data and validate them
        symbol = request.form.get("symbol", "").strip().upper()
        shares = request.form.get("shares")

        if not symbol:
            return apology("Missing stock symbol")

        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Invalid number of shares")

        stock_info = lookup(symbol)

        if stock_info is None:
            return apology("Symbol not found")

        # Extract stock price and calculate total cost
        stock_price = stock_info["price"]
        shares_count = int(shares)
        total_price = shares_count * stock_price

        user_id = session.get("user_id")
        user_data = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)
        available_cash = user_data[0]["cash"]

        if available_cash < total_price:
            return apology("Insufficient funds")

        db.execute("UPDATE users SET cash = cash - :total WHERE id = :user_id",
                   total=total_price, user_id=user_id)

        # Record the transaction
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (:user_id, :symbol, :shares, :price)
        """, user_id=user_id, symbol=symbol, shares=shares_count, price=stock_price)

        flash(f"Successfully purchased {shares_count} shares of {symbol} for {usd(total_price)}")
        return redirect("/")

    # for GET request
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query to get all transactions for user thats currently logged in (this is ordered by the most recent)
    user_id = session["user_id"]
    transactions = db.execute("""
        SELECT symbol, shares, price, timestamp, CASE
            WHEN shares > 0 THEN 'BUY'
            ELSE 'SELL'
        END AS type
        FROM transactions
        WHERE user_id = :user_id
        ORDER BY timestamp DESC
    """, user_id=user_id)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        # Retrieving symbol from form
        symbol = request.form.get("symbol", "").strip().upper()

        if not symbol:
            return apology("You must provide a symbol", 400)
        quote = lookup(symbol)

        # If not valid symbol
        if not quote:
            return apology("Invalid symbol", 400)

        return render_template("quote.html", quote=quote)

    # For GET request
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        confirmation = request.form.get("confirmation").strip()

        # Making sure all fields are there and passwords match
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        elif not confirmation:
            return apology("must confirm password", 400)
        elif password != confirmation:
            return apology("passwords must match", 400)

        # If username exists
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            return apology("that username already exists", 400)

        # Hashing password
        hashed_password = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash, cash) VALUES (?, ?, 10000.0)",
                   username, hashed_password)

        # Logging in user
        user_row = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = user_row[0]["id"]

        return redirect("/")

    # For GET request
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Fetch user's stocks with available shares
    user_id = session["user_id"]
    stocks = db.execute("""
                        SELECT symbol, SUM(shares) as total_shares
                        FROM transactions
                        WHERE user_id = :user_id
                        GROUP BY symbol
                        HAVING total_shares > 0
                        """, user_id=user_id)

    if request.method == "POST":

        # Getting form inputs
        symbol = request.form.get("symbol", "").strip().upper()
        shares = request.form.get("shares", "").strip()

        if not symbol:
            return apology("Must provide symbol", 400)
        if not shares.isdigit() or int(shares) <= 0:
            return apology("Must provide a positive integer number of shares", 400)

        # Convert shares to an integer after its validity is checked
        shares = int(shares)

        # Makes sure user owns the stock and has enough shares to sell
        stock_to_sell = next((stock for stock in stocks if stock["symbol"] == symbol), None)
        if not stock_to_sell:
            return apology("You don't own any shares of that stock", 400)

        if stock_to_sell["total_shares"] < shares:
            return apology("Not enough shares to sell", 400)

        quote = lookup(symbol)
        if not quote:
            return apology("Symbol not found", 400)

        price = quote["price"]
        total_sale = shares * price

        # Updating users cash and logging transaction
        db.execute("UPDATE users SET cash = cash + :total_sale WHERE id = :user_id",
                   total_sale=total_sale, user_id=user_id)
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (:user_id, :symbol, :shares, :price)
        """, user_id=user_id, symbol=symbol, shares=-shares, price=price)

        flash(f"Sold {shares} shares of {symbol} for {usd(total_sale)}!")
        return redirect("/")

    # For GET request
    return render_template("sell.html", stocks=stocks)


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    """Withdraw or add more money"""
    user_id = session["user_id"]

    # Get current cash balance
    current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                              user_id=user_id)[0]["cash"]

    if request.method == "POST":
        # Get the amount of cash added, strip spaces
        cash_added = request.form.get("cash", "").strip()

        if not cash_added or not cash_added.isdigit() or int(cash_added) <= 0:
            return apology("Must provide a positive integer cash amount", 400)
        cash_added = int(cash_added)

        # Update user's cash balance
        db.execute("""
            UPDATE users
            SET cash = cash + :cash_added
            WHERE id = :user_id
        """, user_id=user_id, cash_added=cash_added)

        flash(f"Added ${cash_added} to your account. Your new total is ${current_cash + cash_added}!")
        return redirect("/")

    # For GET request
    return render_template("cash.html", cash=current_cash)
