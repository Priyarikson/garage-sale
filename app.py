import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, url_for, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import urllib.request
from helpers import apology, login_required

UPLOAD_FOLDER = 'static/uploads/'

# Configure application
app = Flask(__name__)

app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def allowed_file(filename):
# return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
@login_required
def index():
    # Display the user id's entries in the database on index.html
    # query for all listing
    selflisting = db.execute(
        "SELECT filename, productname, description, price, time FROM listing WHERE user_id = ?", session["user_id"])

    # Render all listing page.
    return render_template("index.html", selflisting=selflisting)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must providennnn username", 403)

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
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Register user
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Validate username
        username = request.form.get('username')
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        special_chars = ['$', '&', '!']
        # Validate password
        password = request.form.get('password')
        # Validate confirmation
        confirmation = request.form.get('confirmation')

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure the username doesn't exists
        elif len(rows) != 0:
            return apology("username already exists", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not confirmation:
            return apology("must provide password", 400)

        # Ensure confirmation and password are same
        elif not password == confirmation:
            return apology("passwords do not match", 400)

        # Require users’ passwords to have some number of letters, numbers, and/or symbols.
        if len(password) < 8:
            return apology("Make sure your password is atleast 8 letters", 400)

        elif not any(char.isdigit() for char in password):
            return apology("the password should have at least one numeral", 400)

        elif not any(char.isupper() for char in password):
            return apology("the password should have at least one uppercase letter", 400)

        elif not any(char.islower() for char in password):
            return apology("the password should have at least one lowercase letter", 400)

        elif not any(char not in special_chars for char in password):
            return apology('Password should have at least one of the symbols $@#')

        # Hash the user’s password
        else:
            hash = generate_password_hash(password)

            # INSERT the new user into users, storing a hash of the user’s password, not the password itself.

            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

            # Redirect user to home page
            return redirect('/')
     # Else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")



@app.route("/addlisting", methods=["GET", "POST"])
@login_required
def addlisting():
    # Add the user's entry into the database
    # Access form data.
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Validate
        productname = request.form.get("productname")
        description = request.form.get("description")
        price = request.form.get("price")
        location = request.form.get("location")
        email = request.form.get("email")
        phone = request.form.get("phone")
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # For the user currently logged in
        # insert data into database.
        db.execute(
            "INSERT INTO listing ( user_id, filename, productname, description, price, location, email, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            session["user_id"],
            filename,
            productname,
            description,
            price,
            location,
            email,
            phone
        )
        # go back to homepage.
        return redirect("/")

    else:
        return render_template("addlisting.html")


@app.route("/listings")
@login_required
def listings():

    # Display the entries in the database on listing.html
    # query for all listing
    alllisting = db.execute("SELECT filename, productname, description, price, location, email, phone, time FROM listing GROUP BY time ORDER BY time DESC")
# Render all listing page.
    return render_template("listings.html", alllisting=alllisting)