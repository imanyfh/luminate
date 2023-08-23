import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from secondary import apology, login_required
import datetime

# Configure application
app = Flask(__name__)

# Custom filter

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


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    usernameDB = db.execute("SELECT username FROM users WHERE id = ?", user_id)
    username = usernameDB[0]["username"]
    return render_template("index.html", username=username)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide a username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide a password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Logged in successfully!")
        return redirect("/")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    current_year = datetime.datetime.now().year
    """Register user"""
    if request.method == "GET":
        return render_template("register.html", current_year=current_year)
    else:
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Must Provide A Username")
        if not email:
            return apology("Must give an email address")
        if not password:
            return apology("Enter a password")
        if not confirmation:
            return apology("Enter your password again")

        if password != confirmation:
            return apology("Passwords do not match!")

    existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
    if existing_user:
        return apology("Username already exists")

    hash = generate_password_hash(password)
    user = db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, hash)

    session["user_id"] = user

    flash("Thank you for signing up for our website!")
    return redirect("/")


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "POST":
        user_id = session["user_id"]

        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Query the database to get the user's current hash
        current_hash = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0][
            "hash"
        ]

        # Verify old password
        if not check_password_hash(current_hash, old_password):
            return apology("Invalid old password")

        # Ensure new password matches confirmation
        if new_password != confirm_password:
            return apology("Passwords do not match")

        # Generate hash for the new password and update in the database
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

        flash("Password changed successfully")

        return redirect("/")

    else:
        return render_template("changepassword.html")


@app.route("/search" , methods=["GET", "POST"])
@login_required
def search():
    return render_template("search.html")



@app.route("/result" , methods=["GET", "POST"])
@login_required
def result():
    search = request.form.get("search")
    if search:
        users = db.execute("SELECT * FROM users WHERE username LIKE ? LIMIT 50", (search + "%",))
    else:
        users = []
    return render_template("result.html", users=users)





@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session["user_id"]
    usernameDB = db.execute("SELECT username FROM users WHERE id = ?", user_id)
    username = usernameDB[0]["username"]


    if request.method == "POST":
        bio = request.form.get("bio")
        country = request.form.get("country")

        if bio:
            db.execute("INSERT INTO profile (user_id, bio) VALUES (?, ?)", user_id, bio)
        else:
            bio = None
        flash("That was done successfully!")
        return redirect("/")

   # profile = db.execute("SELECT bio FROM profile WHERE user_id = ?", user_id)


    return render_template("profile.html", username=username)



@app.route("/userprofile/<int:user_id>")
@login_required
def userprofile(user_id):
    current_user_id = session["user_id"]
    current_username = db.execute("SELECT username FROM users WHERE id = ?", current_user_id)[0]["username"]

    profile = db.execute("SELECT username, bio FROM users JOIN profile ON users.id = profile.user_id WHERE users.id = ? LIMIT 1", user_id)
    users = db.execute("SELECT * FROM users WHERE id LIKE ?", user_id)


    return render_template("userprofile.html", profile=profile, users=users, current_username=current_username)





@app.route("/post", methods=["GET", "POST"])
@login_required
def Post():
    user_id = session["user_id"]
    usernameDB = db.execute("SELECT username FROM users WHERE id = ?", user_id)
    username = usernameDB[0]["username"]


    if request.method == "POST":
        post = request.form.get("post")

        if post:
            db.execute("INSERT INTO posts (user_id, post) VALUES (?, ?)", user_id, post)
        else:
            post = None
        flash("That was done successfully!")
        return redirect("/")

   # profile = db.execute("SELECT bio FROM profile WHERE user_id = ?", user_id)


    return render_template("post.html", username=username)



@app.route("/userpost/<int:user_id>")
@login_required
def userpost(user_id):
    current_user_id = session["user_id"]
    current_username = db.execute("SELECT username FROM users WHERE id = ?", current_user_id)[0]["username"]
    current_date = datetime.datetime.now().strftime('%B %d, %Y')

    posts = db.execute("SELECT username, post FROM users JOIN posts ON users.id = posts.user_id WHERE users.id = ? ", user_id)
    users = db.execute("SELECT * FROM users WHERE id LIKE ?", user_id)

    return render_template("userpost.html", posts=posts, users=users, current_username=current_username, current_date=current_date)


@app.route("/myposts")
@login_required
def myposts():
    current_user_id = session["user_id"]
    current_username = db.execute("SELECT username FROM users WHERE id = ?", current_user_id)[0]["username"]
    current_date = datetime.datetime.now().strftime('%B %d, %Y')

    posts = db.execute("SELECT username, post FROM users JOIN posts ON users.id = posts.user_id WHERE users.id = ? ", current_user_id)
    users = db.execute("SELECT * FROM users WHERE id LIKE ?", current_user_id)

    return render_template("myposts.html", posts=posts, users=users, current_username=current_username, current_date=current_date)

