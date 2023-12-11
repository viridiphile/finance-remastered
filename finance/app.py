import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import re
import random

from helpers import apology, login_required, lookup, usd, lookup_batch

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/portfolio")
@login_required
def portfolio():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions = db.execute("SELECT symbol, name, SUM(shares) AS shares, price, price * shares AS total FROM transactions WHERE user_id = ?  GROUP BY symbol", user_id)

    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    cash_total = cash
    for row in transactions:
        cash_total += row["total"]

    return render_template("portfolio.html", transactions = transactions, cash = cash, total = cash_total)

@app.route("/")
def index():
    STOCKS = ["MCHP", "ATVI", "GOOGL", "TEAM", "AAPL", "KO", "PFE", "NFLX"]

    pick = random.sample(range(len(STOCKS)), 4)

    selected = []
    for index in pick:
        selected.append(STOCKS[index])   

    result = []
    
    shares = lookup_batch(selected)
    for share in shares:
        result.append(
                { 
                    "symbol": share,
                    "name": shares[share]["quote"]["companyName"],
                    "price": shares[share]["quote"]["latestPrice"]
                }
            )
    return render_template("index.html", selected=result)
    """ name1=stocks1["name"], price1=stocks1["price"], symbol1=stocks1["symbol"], name2=stocks2["name"], price2=stocks2["price"], symbol2=stocks2["symbol"], name3=stocks3["name"], price3=stocks3["price"], symbol3=stocks3["symbol"], name4=stocks4["name"], price4=stocks4["price"], symbol4=stocks4["symbol"] """

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # 3
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must input a symbol")

        symbol = symbol.upper()
        stocks = lookup(symbol)

        if stocks == None:
            return apology("Symbol does not exist")

        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except:
            return apology("That ain't a number of shares")

        if shares <= 0:
            return apology("Must be a positive amount")

        user_id = session["user_id"]
        cash_available = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        share_name = stocks["name"]
        price = stocks["price"]
        transaction_value = price * shares

        # Money check
        if cash_available < transaction_value:
            return apology("Insufficient funds")
        updated_cash = cash_available - transaction_value

        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)

        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, type) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, symbol, share_name, shares, price, 'buy')

        flash("The purchase has been made!")

        return redirect("/portfolio")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/portfolio")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # 2
    # Allows to look up a stock's current price
    # input of stock's symbol required, html name="symbol"
    # submit input via "post" to "/quote"
    # 2 new templates quote.html, quoted.html

    """Odds are you’ll want to create two new templates (e.g., quote.html and quoted.html). When a user visits /quote via GET, render one of those templates, inside of which should be an HTML form that submits to /quote via POST. In response to a POST, quote can render that second template, embedding within it one or more values from lookup."""

    

    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must input a symbol")

        stocks = lookup(symbol.upper())

        if stocks == None:
            return apology("Symbol does not exist")
        return render_template("quoted.html", name=stocks["name"], price=stocks["price"], symbol=stocks["symbol"])# from backend to frontend
    else :
        symbol = request.args.get('symbol') 

        if not symbol:
            return render_template("quote.html")

        stocks = lookup(symbol.upper())

        if stocks == None:
            return apology("Symbol does not exist")
        return render_template("quoted.html", name=stocks["name"], price=stocks["price"], symbol=stocks["symbol"])
    

        


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # 1

    # Registering via form
    # Input a username, in html name="username", if empty or taken send an apology
    # input a password, in html name="password", then the same password in html="confirmation"
    # render an apology is block is blank or they dont match

    # submit form via post
    # insert a new user into users, storing a hash of the user's password, not the password itself
    # we want to create new template register.html thats similar to login.html

    # when u implement this you will
    if request.method == "POST":
        # temporary for comfort use variables then change to requests
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # check for blank
        if not username:
            return apology("Username required")

        if not password:
            return apology("Password required")

        if not confirmation:
            return apology("Confirmation required")

        if password != confirmation:
            return apology("Passwords do not match")

        check = True
        #re.search("[a-z0-9A-Z\s]", password)
        while check:
            if (len(password) < 8 or len(password) > 12):
                break
            elif not re.search("[a-z]", password):
                break
            elif not re.search("[0-9]", password):
                break
            elif not re.search("[A-Z]", password):
                break
            elif re.search("\s", password):
                break
            else:
                check = False

        if check:
            return apology("Password does not meet requirements")

        hash = generate_password_hash(password)

        # register user in db
        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("Username is taken")
        # once we are registered
        # start session, we go to website
        session["user_id"] = new_user
        return redirect("/portfolio")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must input a symbol")

        stocks = lookup(symbol.upper())

        if stocks == None:
            return apology("Symbol does not exist")

        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except:
            return apology("That ain't a number of shares")

        if shares <= 0:
            return apology("Must be a positive amount")

        user_id = session["user_id"]

        share_name = stocks["name"]
        price = stocks["price"]
        transaction_value = shares * price

        user_shares = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        if shares > user_shares:
            return apology("Insufficient amount of shares")

        updated_cash = user_cash + transaction_value

        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)

        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, type) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, share_name, (-1)*shares, transaction_value, 'sell')

        flash("The sell has been made!")

        return redirect("/portfolio")

    else:
        user_id = session["user_id"]
        user_symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)

        return render_template("sell.html", symbols=[row["symbol"] for row in user_symbols])


@app.route("/graph")
@login_required
def graph():
    # """Display chart of portfolio"""
    # rows = db.execute("SELECT symbol,SUM(shares) FROM transactions WHERE user_id = (:id) GROUP BY symbol", id=session["user_id"])

    # # Pop symbols that have 0 shares
    # for i in range(0, len(rows)):
    #     if rows[i]["SUM(shares)"] == 0:
    #         rows.pop(i)

    # # Obtain current prices and company names of symbols
    # for item in rows:
    #     item["price"] = lookup(item["symbol"])["price"]
    #     item["name"] = lookup(item["symbol"])["name"]

    # # Obtain cash on hand
    # cash_rows = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
    # cash = cash_rows[0]['cash']

    # # Obtain list of symbols (add cash)
    # symbols = []
    # for item in rows:
    #     symbols.append(item["symbol"])
    # symbols.append("CASH")

    # # Obtain list of totals (add cash)
    # totals = []
    # for item in rows:
    #     totals.append(item["price"] * item["SUM(shares)"])
    # totals.append(cash)

    # Pass list of lists we will use for the Chart
    # return render_template("graph.html", symbols=symbols, totals=totals)
    return render_template("graph.html")

# echo to terminal to print smth
# pk_02094697040142be88249b444d048556
# inputting alphabetical strings into forms when only numbers are expected,
# inputting floating-point values into forms when only integers are expected,
# trying to spend more cash than a user has,
# trying to sell more shares than a user has,
# inputting an invalid stock symbol, and
# including potentially dangerous characters like ' and ; in SQL queries.


# PASSWORD: Mj80AM29a - GEORGE
# Immanuel = KDArr965O~


# add borders
# add shares to front page