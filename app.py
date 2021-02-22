from flask import Flask, flash, jsonify, render_template, redirect, request, session, send_file
from flask_session import Session
import os, time, fnmatch
from werkzeug.security import check_password_hash, generate_password_hash
from cs50 import SQL
from datetime import date
from tempfile import mkdtemp
from glob import glob
import time

from helpers import login_required

db = SQL("sqlite:///data.db")

app = Flask(__name__)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.route("/", methods=["POST", "GET"])
def index():
    update()
    tmp = db.execute("SELECT * FROM content")
    print(tmp)
    return render_template("index.html", data=tmp)

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        # Store the user input
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        passhash = generate_password_hash(password)

        rows = db.execute("SELECT * FROM users WHERE email=:email", email=email)

        if not rows:
            db.execute("INSERT INTO users (username, password, email) VALUES (:username, :password, :email)", username=username, password=passhash, email=email)
            return render_template("reg-login.html", reg=2, passhash = passhash)
    else:
        return render_template("reg-login.html", reg=1)

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        rows = db.execute("SELECT * FROM users WHERE email=:email", email=email)

        if not rows:
            return render_template("reg-login.html", reg=0, msg="That user does not exist.")

        if (check_password_hash(rows[0]["password"], password) == False):
            return render_template("reg-login.html", reg=0, msg="Can't find a user with those credentials, please double check them.")
        else:
            session["user_id"] = rows[0]["id"]
            return redirect("/")
    else:
        return render_template("reg-login.html", reg=0)

@app.route("/logout")
def logout():
    # Clear the current session to log the user out, and redirect them to the homepage
    session.clear()
    return redirect("/")

@app.route("/account")
@login_required
def account():
    rows = db.execute("SELECT * FROM users WHERE id=:id", id = session["user_id"])
    passhash = rows[0]["password"]

    return render_template("account.html", passhash=passhash, data = rows[0])

@app.route("/blogpage", methods=["POST"])
def blogpage():
    if request.method == "POST":
        identity = request.form['id']
        rows = db.execute("SELECT * FROM content WHERE id=:id", id = identity)
        commentData = db.execute("SELECT * FROM comments")

        path = rows[0]["path"]
        return render_template(path[7:] + "content.html", data=rows[0], commentData=commentData)

@app.route("/passwordUpdate", methods=["POST"])
@login_required
def passwordUpdate():
    email = request.form.get("email")
    oldPassword = request.form.get("oldPassword")
    newPassword = request.form.get("newPassword")

    tmp = db.execute("SELECT * FROM users WHERE email=:email", email = email)

    if check_password_hash(tmp[0]["password"], oldPassword) == False:
        return render_template("account.html", msg = "Please check your credentials", data=tmp[0])
    else:
        db.execute("UPDATE users SET password=:password WHERE email=:email", password=generate_password_hash(newPassword), email=email)
        return render_template("account.html", msg = "Credentials changed successfully!", data=tmp[0])

@app.route("/readingList", methods=['POST', 'GET'])
@login_required
def readingList():
    if request.method == "POST":
        if request.form.get("del"):
            contentID = request.form.get("contentID")
            db.execute("DELETE FROM readLater WHERE userID=:userID AND contentID=:contentID", userID=session["user_id"], contentID=contentID)
            return redirect("/readingList")
        contentID = request.form.get("id")
        db.execute("INSERT INTO readLater (userID, contentID) VALUES (:userID, :contentID)", userID=session["user_id"], contentID=contentID)
        return redirect("/")
    if request.method == "GET":
        data = db.execute("SELECT * FROM content JOIN readLater ON readLater.contentID=content.id WHERE readLater.userID=:userID", userID = session["user_id"])
        return render_template("readingList.html", data = data)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/comments", methods=["POST"])
def comments():
    comment = request.form.get("comment")
    contentID = request.form.get("contentID")
    timeNow = time.time()

    username = db.execute("SELECT * FROM users WHERE id=:id", id = session["user_id"])

    db.execute("INSERT INTO comments (contentID, userID, comment, time, name) VALUES (:contentID, :userID, :comment, :time, :name)", contentID=contentID, userID=session["user_id"], comment=comment, time=timeNow, name=username[0]['username'])

    rows = db.execute("SELECT * FROM content WHERE id=:id", id = contentID)
    commentData = db.execute("SELECT * FROM comments")
    path = rows[0]["path"]
    return render_template(path[7:] + "content.html", data=rows[0], commentData=commentData)

@app.route("/deleteComment", methods=["POST"])
def deleteComment():
    commentID = request.form.get("commentID")
    contentID = request.form.get("contentID")
    db.execute("DELETE FROM comments WHERE id=:id", id=commentID)

    rows = db.execute("SELECT * FROM content WHERE id=:id", id = contentID)
    commentData = db.execute("SELECT * FROM comments")
    path = rows[0]["path"]
    return render_template(path[7:] + "content.html", data=rows[0], commentData=commentData)

@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    if request.method == "GET":
        data = db.execute("SELECT * FROM comments JOIN content ON comments.contentID=content.id WHERE userID=:userID", userID=session["user_id"])
        contentData = []
        return render_template("history.html", data=data, contentData=contentData)


def update():
    path = './static/Content/*/'

    found = 1
    today = date.today()

    db = SQL("sqlite:///data.db")

    output = glob(path)

    tmp = db.execute("SELECT * FROM content")

    for x in output:
        found = 1
        for y in tmp:
            if y["path"] == x[2:]:
                found = 0
        if found == 1:
            f = open(x + 'content.txt', 'r')
            Lines = f.readlines()
            print(Lines[0])
            db.execute("INSERT INTO content (name, category, date, path) VALUES (:name, :category, :date, :path)", name = Lines[0][:-1], category = Lines[1], date=today.strftime("%B %d, %Y"), path = x[2:])
