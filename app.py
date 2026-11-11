import hmac
import os
import secrets
from functools import wraps

from flask import Flask, request, render_template_string, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY must be configured.")

database_url = os.environ.get("DATABASE_URL", "sqlite:///students.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production")
db = SQLAlchemy(app)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # Retained for compatibility with the previous schema; no email is collected.
    email = db.Column(db.String(100), nullable=False, default="")
    phone = db.Column(db.String(30), nullable=False)

with app.app_context():
    db.create_all()

def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

def csrf_valid():
    return bool(session.get("_csrf_token") and request.form.get("_csrf_token") and
                hmac.compare_digest(session["_csrf_token"], request.form["_csrf_token"]))

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

@app.route("/", methods=["GET", "POST"])
def register():
    message = error = None
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh the page and try again."
        else:
            name = request.form.get("name", "").strip()
            phone = request.form.get("phone", "").strip()
            if not name or len(name) > 100:
                error = "Enter a valid full name (maximum 100 characters)."
            elif not phone or len(phone) > 30:
                error = "Enter a valid phone number (maximum 30 characters)."
            else:
                db.session.add(Student(name=name, email="", phone=phone))
                db.session.commit()
                message = "Registration successful. Thank you!"
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Registration Form</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font-family:Arial,sans-serif;background:linear-gradient(135deg,#eaf3ff,#f7faff);color:#17243a}
.card{width:100%;max-width:430px;background:white;padding:32px;border-radius:18px;box-shadow:0 14px 45px #1946821f}
h1{text-align:center;color:#1456a0;margin:0 0 8px}.intro{text-align:center;color:#66758a;margin:0 0 26px}
label{display:block;margin:17px 0 8px;font-weight:700}input{width:100%;padding:14px;border:1px solid #d5deea;border-radius:9px;font-size:16px}
input:focus{outline:2px solid #2376d2}button{width:100%;margin-top:24px;padding:14px;border:0;border-radius:9px;background:#1768bd;color:white;font-size:16px;font-weight:700;cursor:pointer}
.notice{padding:12px;border-radius:8px;margin:16px 0}.success{background:#e8f7ed;color:#176334}.error{background:#fff0ef;color:#a12a22}
.admin{display:block;margin-top:22px;text-align:center;color:#1768bd}
</style></head><body><main class="card"><h1>Registration</h1><p class="intro">Please enter your details below.</p>
{% if message %}<div class="notice success" role="status">{{message}}</div>{% endif %}{% if error %}<div class="notice error" role="alert">{{error}}</div>{% endif %}
<form method="POST"><input type="hidden" name="_csrf_token" value="{{token}}">
<label for="name">Full Name</label><input id="name" name="name" type="text" maxlength="100" placeholder="Enter your full name" autocomplete="name" required>
<label for="phone">Phone Number</label><input id="phone" name="phone" type="tel" maxlength="30" placeholder="Enter your phone number" autocomplete="tel" required>
<button type="submit">Register</button></form><a class="admin" href="{{url_for('admin_login')}}">Admin login</a></main></body></html>
""",message=message,error=error,token=csrf_token())

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    error = None
    configured_user, configured_password = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
    if not configured_user or not configured_password:
        return "Admin login is not configured.", 503
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh and try again."
        else:
            username, password = request.form.get("username",""), request.form.get("password","")
            if hmac.compare_digest(username,configured_user) and hmac.compare_digest(password,configured_password):
                session.clear()
                session["is_admin"] = True
                session["_csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin"))
            error = "Incorrect username or password."
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title>
<style>body{font-family:Arial;background:#edf4fc;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}.card{background:white;padding:30px;border-radius:16px;width:100%;max-width:390px;box-shadow:0 12px 36px #173b641a}h1{color:#1456a0;margin-top:0}label{display:block;margin:16px 0 7px;font-weight:bold}input{width:100%;padding:13px;border:1px solid #ccd7e5;border-radius:8px;box-sizing:border-box;font-size:16px}button{width:100%;padding:13px;margin-top:22px;border:0;border-radius:8px;background:#1768bd;color:white;font-weight:bold;font-size:16px}.error{background:#fff0ef;color:#a12a22;padding:10px;border-radius:8px}a{display:block;text-align:center;margin-top:18px;color:#1768bd}</style></head>
<body><main class="card"><h1>Admin Login</h1>{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="hidden" name="_csrf_token" value="{{token}}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Log In</button></form><a href="/">Back to registration</a></main></body></html>
""",error=error,token=csrf_token())

@app.route("/admin")
@admin_required
def admin():
    students = Student.query.order_by(Student.id.desc()).all()
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Dashboard</title>
<style>body{font-family:Arial;margin:0;padding:24px;background:#f5f8fc;color:#17243a}.wrap{max-width:1000px;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{color:#1456a0}table{width:100%;border-collapse:collapse;background:white;margin-top:20px}th,td{padding:13px;text-align:left;border-bottom:1px solid #e4eaf1}th{background:#1768bd;color:white}.empty{padding:22px;background:white;border-radius:10px;margin-top:20px}button{padding:8px 12px;border:0;border-radius:6px;background:#b83232;color:white;cursor:pointer}a{color:#1768bd}@media(max-width:600px){body{padding:14px}th,td{padding:9px;font-size:14px}}</style></head>
<body><main class="wrap"><div class="top"><div><h1>Admin Dashboard</h1><p>{{students|length}} registration(s)</p></div>
<form method="POST" action="{{url_for('admin_logout')}}"><input type="hidden" name="_csrf_token" value="{{token}}"><button type="submit">Log Out</button></form></div>
{% if students %}<table><thead><tr><th>#</th><th>Full Name</th><th>Phone Number</th><th>Action</th></tr></thead><tbody>
{% for student in students %}<tr><td>{{student.id}}</td><td>{{student.name}}</td><td>{{student.phone}}</td><td><form method="POST" action="{{url_for('delete_student',student_id=student.id)}}" onsubmit="return confirm('Delete this registration?')"><input type="hidden" name="_csrf_token" value="{{token}}"><button type="submit">Delete</button></form></td></tr>{% endfor %}
</tbody></table>{% else %}<p class="empty">No registrations yet.</p>{% endif %}<p><a href="/">Open registration form</a></p></main></body></html>
""",students=students,token=csrf_token())

@app.route("/admin/logout",methods=["POST"])
@admin_required
def admin_logout():
    if not csrf_valid(): return "Invalid request token.",400
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/delete/<int:student_id>",methods=["POST"])
@admin_required
def delete_student(student_id):
    if not csrf_valid(): return "Invalid request token.",400
    student = db.session.get(Student,student_id)
    if student:
        db.session.delete(student)
        db.session.commit()
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(debug=False)
