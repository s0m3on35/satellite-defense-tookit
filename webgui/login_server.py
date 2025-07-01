# webgui/login_server.py
from flask import Flask, request, render_template_string, redirect, session
import hashlib

app = Flask(__name__)
app.secret_key = "SATSECULTRAKEY123"  # Replace for prod

USERNAME = "admin"
PASSWORD_HASH = hashlib.sha256("nasa123".encode()).hexdigest()

LOGIN_HTML = """
<html><head><title>Login</title></head>
<body>
  <h2>Satellite Defense Toolkit Login</h2>
  <form method="POST">
    Username: <input name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="Login">
  </form>
</body></html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = hashlib.sha256(request.form["password"].encode()).hexdigest()
        if u == USERNAME and p == PASSWORD_HASH:
            session["user"] = u
            return redirect("/dashboard")
    return render_template_string(LOGIN_HTML)

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return "<h1>Welcome to the Dashboard</h1><a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
