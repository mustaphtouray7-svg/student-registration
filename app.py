import hmac
import os
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from functools import wraps

from flask import Flask, request, render_template_string, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY must be configured.")

database_url = os.environ.get("DATABASE_URL", "sqlite:///students.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg2://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)
db = SQLAlchemy(app)


class Student(db.Model):
    """Legacy table retained so older registration records are not destroyed."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, default="")
    phone = db.Column(db.String(30), nullable=False)


class WebsiteVisitor(db.Model):
    """Privacy-minimal visitor analytics; no IP address or personal identity is collected."""
    id = db.Column(db.Integer, primary_key=True)
    visitor_key = db.Column(db.String(64), nullable=False, unique=True, index=True)
    first_visited_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    last_visited_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    visit_count = db.Column(db.Integer, nullable=False, default=1)
    last_path = db.Column(db.String(200), nullable=False, default="/")


class ScholarshipApplicant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    second_name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    program = db.Column(db.String(150), nullable=False)
    degree = db.Column(db.String(20), nullable=False)
    wave_transaction_reference = db.Column(db.String(100), nullable=True)
    payment_method = db.Column(db.String(20), nullable=False, default="Wave")
    payment_status = db.Column(db.String(20), nullable=False, default="Pending")
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())


with app.app_context():
    db.create_all()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def csrf_valid():
    submitted = request.form.get("_csrf_token", "")
    stored = session.get("_csrf_token", "")
    return bool(submitted and stored and hmac.compare_digest(stored, submitted))


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/global-scholarship-hub-logo.svg")
def scholarship_hub_logo():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "global-scholarship-hub-logo.svg")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        # Record every registration-page opening as a separate visit event.
        # This avoids relying on the Flask login session or browser cookies.
        db.session.add(WebsiteVisitor(
            visitor_key=secrets.token_urlsafe(32),
            visit_count=1,
            last_path="/",
        ))
        db.session.commit()

    message = error = None
    wave_base_url = os.environ.get("WAVE_PAYMENT_URL", "").strip()
    selected_degree = ""

    def payment_url_for_degree(degree_value):
        amounts = {"Bachelor's": "5", "Master's": "8", "PhD": "12"}
        amount = amounts.get(degree_value)
        if not wave_base_url or not amount:
            return ""
        parts = urlsplit(wave_base_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query["amount"] = amount
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh the page and try again."
        else:
            first_name = request.form.get("first_name", "").strip()
            second_name = request.form.get("second_name", "").strip()
            phone = request.form.get("phone", "").strip()
            country = request.form.get("country", "").strip()
            program = request.form.get("program", "").strip()
            degree = request.form.get("degree", "").strip()
            selected_degree = degree
            wave_reference = request.form.get("wave_transaction_reference", "").strip()

            if not first_name or len(first_name) > 80:
                error = "Enter a valid first name (maximum 80 characters)."
            elif not second_name or len(second_name) > 80:
                error = "Enter a valid second name (maximum 80 characters)."
            elif not phone or len(phone) > 30:
                error = "Enter a valid phone number (maximum 30 characters)."
            elif not country or len(country) > 100:
                error = "Enter the country you applied to."
            elif not program or len(program) > 150:
                error = "Enter the scholarship program you applied for."
            elif degree not in {"Bachelor's", "Master's", "PhD"}:
                error = "Choose Bachelor's, Master's, or PhD."
            elif not wave_reference or len(wave_reference) > 100:
                error = "Complete your Wave payment and enter the transaction reference before submitting."
            else:
                applicant = ScholarshipApplicant(
                    first_name=first_name,
                    second_name=second_name,
                    phone=phone,
                    country=country,
                    program=program,
                    degree=degree,
                    wave_transaction_reference=wave_reference or None,
                    payment_method="Wave",
                    payment_status="Pending Verification",
                )
                db.session.add(applicant)
                db.session.commit()
                message = f"Your registration has been received successfully. Your Global Scholarship Hub number is GSH{applicant.id}."
    wave_url = payment_url_for_degree(selected_degree)
    return render_template_string("""
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Applicant Registration</title>
<meta name="description" content="Global Scholarship Hub applicant registration form.">
<meta property="og:title" content="Applicant Registration">
<meta property="og:description" content="Global Scholarship Hub applicant registration form.">
<style>
*{box-sizing:border-box}body{margin:0;padding:24px;min-height:100vh;background:#eef3f9;font-family:Arial,sans-serif;color:#17243a}
.card{max-width:620px;margin:24px auto;background:#fff;padding:0;border-radius:18px;overflow:hidden;box-shadow:0 14px 45px #1946821f}
.registration-banner{padding:38px 28px 30px;text-align:center;color:#fff;background:linear-gradient(rgba(8,35,75,.48),rgba(8,35,75,.72)),url("/global-scholarship-hub-logo.svg") center center/cover no-repeat}
.brand{text-align:center;color:#fff;font-size:13px;font-weight:800;letter-spacing:1.3px;text-shadow:0 1px 4px #000}
h1{text-align:center;color:#fff;margin:8px 0;text-shadow:0 2px 5px #000}.intro{text-align:center;color:#fff;line-height:1.5;margin:0;text-shadow:0 1px 4px #000}.form-content{padding:30px}
h2{font-size:17px;color:#1456a0;margin:25px 0 12px;border-bottom:1px solid #e6edf5;padding-bottom:9px}
label{display:block;margin:14px 0 7px;font-weight:700;font-size:14px}
input,select{width:100%;padding:13px;border:1px solid #d5deea;border-radius:9px;font-size:16px;background:#fff;color:#17243a}
input:focus,select:focus{outline:2px solid #2376d2}
.hint{font-size:12px;color:#718096;margin-top:5px}
.wave{border:1px solid #d7e8f2;background:#f7fcff;padding:20px;border-radius:12px;margin-top:10px;text-align:center}
.wave-brand{display:flex;align-items:center;justify-content:center;gap:9px;margin-bottom:15px}
.wave-icon{width:38px;height:38px;border-radius:11px;background:#1dc8ff;display:grid;place-items:center;color:#fff;font-size:25px;font-weight:900;line-height:1}
.wave-word{font-size:27px;font-weight:800;letter-spacing:-1.5px;color:#101820}
.wave-title{font-weight:800;color:#167447;margin-bottom:14px}
.pay{display:block;text-align:center;text-decoration:none;background:#16a66a;color:#fff;padding:13px;border-radius:9px;font-weight:800}
.pay.disabled{background:#9bb8a8;pointer-events:none}
button{width:100%;margin-top:24px;padding:15px;border:0;border-radius:9px;background:#1768bd;color:white;font-size:16px;font-weight:800;cursor:pointer}
.notice{padding:13px;border-radius:9px;margin:16px 0;line-height:1.4}.success{background:#e8f7ed;color:#176334}.error{background:#fff0ef;color:#a12a22}
.admin{display:block;margin-top:22px;text-align:center;color:#1768bd;font-size:13px}
@media(max-width:520px){body{padding:10px}.card{margin:10px auto}.registration-banner{padding:30px 18px 24px}.form-content{padding:21px 17px}}
</style></head>
<body><main class="card">
<header class="registration-banner"><div class="brand">APPLICANT REGISTRATION</div>
<h1>Applicant Registration</h1>
<p class="intro">This form is for students who have already applied for a scholarship. Please enter your details carefully.</p></header>
<div class="form-content">
{% if message %}<div class="notice success" role="status">{{message}}</div>{% endif %}
{% if error %}<div class="notice error" role="alert">{{error}}</div>{% endif %}
<form method="POST" action="/">
<input type="hidden" name="_csrf_token" value="{{token}}">
<h2>Personal Information</h2>
<label for="first_name">First Name</label><input id="first_name" name="first_name" maxlength="80" autocomplete="given-name" required>
<label for="second_name">Second Name</label><input id="second_name" name="second_name" maxlength="80" autocomplete="family-name" required>
<label for="phone">Phone Number</label><input id="phone" name="phone" type="tel" maxlength="30" placeholder="Include country code" autocomplete="tel" required>
<h2>Scholarship Application</h2>
<label for="country">Country Applied To</label><input id="country" name="country" maxlength="100" placeholder="Enter the country" required>
<label for="program">Program Applied For</label><input id="program" name="program" maxlength="150" placeholder="Enter your course or program" required>
<label for="degree">Degree Level</label>
<select id="degree" name="degree" required><option value="">Select degree level</option><option value="Bachelor's" {% if selected_degree == "Bachelor's" %}selected{% endif %}>Bachelor's Degree</option><option value="Master's" {% if selected_degree == "Master's" %}selected{% endif %}>Master's Degree</option><option value="PhD" {% if selected_degree == "PhD" %}selected{% endif %}>PhD</option></select>
<h2>Payment</h2>
<div class="wave">
<div class="wave-brand" aria-label="Wave"><span class="wave-icon" aria-hidden="true">w</span><span class="wave-word">wave</span></div>
<div class="wave-title">Wave Payment Only</div>
<div id="payment-amount" class="hint" aria-live="polite">{% if wave_url %}Selected payment: {{ "$5" if selected_degree == "Bachelor's" else "$8" if selected_degree == "Master's" else "$12" }}{% else %}Select your degree level to see the payment amount{% endif %}</div>
<a id="wave-pay" class="pay{% if not wave_url %} disabled{% endif %}" href="{{url_for('wave_payment')}}" {% if not wave_url %}aria-disabled="true"{% endif %} target="_self">Pay with Wave</a>
<label for="wave_transaction_reference">Wave Transaction Reference</label>
<input id="wave_transaction_reference" name="wave_transaction_reference" maxlength="100" placeholder="Enter the reference shown after payment" required>
<p class="hint">Payment is required. After completing payment in Wave, enter your transaction reference to submit. Your payment will remain pending verification until checked by the admin.</p>
</div>
<button type="submit">Submit Registration</button>
</form>
<a class="admin" href="{{url_for('admin_login')}}">Admin Login</a>
</div></main>
<script>
(function(){
  const degree = document.getElementById('degree');
  const pay = document.getElementById('wave-pay');
  const amount = document.getElementById('payment-amount');
  const prices = {"Bachelor's":5,"Master's":8,"PhD":12};
  function updatePayment(){
    const price = prices[degree.value];
    if(!price){
      pay.href = '{{url_for("wave_payment")}}';
      pay.classList.add('disabled'); pay.setAttribute('aria-disabled','true');
      amount.textContent = 'Select your degree level to see the payment amount'; return;
    }
    pay.href = '{{url_for("wave_payment")}}?degree=' + encodeURIComponent(degree.value);
    pay.classList.remove('disabled'); pay.removeAttribute('aria-disabled');
    amount.textContent = 'Selected payment: 
  updatePayment();
})();
</script>
</body></html>
""", message=message, error=error, token=csrf_token(), wave_url=wave_url)


@app.route("/pay")
def wave_payment():
    degree_value = request.args.get("degree", "")
    amounts = {"Bachelor's": "5", "Master's": "8", "PhD": "12"}
    amount = amounts.get(degree_value)
    base_url = os.environ.get("WAVE_PAYMENT_URL", "").strip()
    if not amount:
        return "Please return to the registration form and select your degree level first.", 400
    if not base_url:
        return "Wave payment is not configured. Please contact the site administrator.", 503
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["amount"] = amount
    payment_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return redirect(payment_url, code=302)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    configured_user = os.environ.get("ADMIN_USERNAME", "").strip()
    configured_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not configured_user or not configured_password:
        return "Admin login is not configured.", 503
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh and try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            username_matches = hmac.compare_digest(username.casefold(), configured_user.casefold())
            password_matches = hmac.compare_digest(password, configured_password)
            if username_matches and password_matches:
                session.clear()
                session["is_admin"] = True
                session["_csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin"))
            error = "Incorrect username or password."
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login | Global Scholarship Hub</title>
<style>body{font-family:Arial;background:#edf4fc;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}.card{background:white;padding:30px;border-radius:16px;width:100%;max-width:390px;box-shadow:0 12px 36px #173b641a}.brand-logo{width:100%;margin:0 auto 18px;text-align:center}.brand-logo img{display:block;width:100%;max-height:210px;object-fit:contain;border-radius:12px}h1{color:#1456a0;margin-top:0;text-align:center}label{display:block;margin:16px 0 7px;font-weight:bold}input{width:100%;padding:13px;border:1px solid #ccd7e5;border-radius:8px;box-sizing:border-box;font-size:16px}button{width:100%;padding:13px;margin-top:22px;border:0;border-radius:8px;background:#1768bd;color:white;font-weight:bold;font-size:16px}.error{background:#fff0ef;color:#a12a22;padding:10px;border-radius:8px}a{display:block;text-align:center;margin-top:18px;color:#1768bd}.password-row{position:relative}.password-row input{padding-right:56px}.toggle-password{position:absolute;right:7px;top:50%;transform:translateY(-50%);width:42px;height:42px;margin:0;padding:0;border:0;border-radius:7px;background:transparent;color:#1456a0;font-size:22px;cursor:pointer}.toggle-password:focus{outline:2px solid #2376d2}</style></head>
<body><main class="card"><div class="brand-logo"><img src="/global-scholarship-hub-logo.svg" alt="Global Scholarship Hub logo"></div><h1>Admin Login</h1>{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="hidden" name="_csrf_token" value="{{token}}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>
<label for="password">Password</label><div class="password-row"><input id="password" name="password" type="password" autocomplete="current-password" required><button class="toggle-password" id="toggle-password" type="button" aria-label="Show password" aria-pressed="false" title="Show password">👁</button></div><button type="submit">Log In</button></form><a href="/">Back to registration</a></main><script>
const passwordField=document.getElementById("password");
const togglePassword=document.getElementById("toggle-password");
togglePassword.addEventListener("click",function(){
  const show=passwordField.type==="password";
  passwordField.type=show?"text":"password";
  togglePassword.textContent=show?"🙈":"👁";
  togglePassword.setAttribute("aria-label",show?"Hide password":"Show password");
  togglePassword.setAttribute("title",show?"Hide password":"Show password");
  togglePassword.setAttribute("aria-pressed",String(show));
});
</script></body></html>
""", error=error, token=csrf_token())


@app.route("/admin")
@admin_required
def admin():
    applicants = ScholarshipApplicant.query.order_by(ScholarshipApplicant.created_at.desc()).all()
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    legacy_count = Student.query.count()
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Applicant Dashboard | Global Scholarship Hub</title>
<style>
body{font-family:Arial,sans-serif;margin:0;padding:22px;background:#f5f8fc;color:#17243a}.wrap{max-width:1200px;margin:auto}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{color:#1456a0}
.table-wrap{overflow-x:auto;background:white;border-radius:12px;margin-top:20px}table{width:100%;border-collapse:collapse;min-width:1050px}
th,td{padding:12px;text-align:left;border-bottom:1px solid #e4eaf1;font-size:13px}th{background:#1768bd;color:white}
button{padding:8px 12px;border:0;border-radius:6px;background:#b83232;color:white;cursor:pointer}
.logout{background:#1768bd}a{color:#1768bd}.empty{padding:22px;background:white;border-radius:10px;margin-top:20px}
.pending{color:#996515;font-weight:bold}.meta{color:#64748b;font-size:13px}
</style></head><body><main class="wrap">
<div class="top"><div><h1>Global Scholarship Hub</h1><p><a href="{{url_for('admin_visitors')}}" style="display:inline-block;background:#1768bd;color:white;padding:12px 16px;border-radius:8px;text-decoration:none;font-weight:bold">OPEN WEBSITE VISITORS ({{visitors|length}})</a></p><p class="meta"><strong>{{visitors|length}} page visit(s)</strong> · {{applicants|length}} applicant registration(s)</p></div>
<form method="POST" action="{{url_for('admin_logout')}}"><input type="hidden" name="_csrf_token" value="{{token}}"><button class="logout" type="submit">Log Out</button></form></div>
<h2 style="color:#1456a0;margin-top:34px">Website Visitors</h2>
<p class="meta">Every opening of the Applicant Registration page is listed below. Visitor numbers are anonymous; no IP addresses are collected.</p>
{% if visitors %}<div class="table-wrap"><table style="min-width:720px"><thead><tr>
<th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visit Count</th><th>Last Page</th>
</tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%Y-%m-%d %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%Y-%m-%d %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="empty">No website visits recorded yet. New visits will appear here.</p>{% endif %}
<p class="meta">Older student-registration records retained in the database: {{legacy_count}}.</p>
{% if applicants %}<div class="table-wrap"><table><thead><tr>
<th>GSH Number</th><th>First Name</th><th>Second Name</th><th>Phone</th><th>Country</th><th>Program</th><th>Degree</th><th>Payment</th><th>Registered</th><th>Action</th>
</tr></thead><tbody>
{% for a in applicants %}<tr><td><strong>GSH{{a.id}}</strong></td><td>{{a.first_name}}</td><td>{{a.second_name}}</td><td>{{a.phone}}</td><td>{{a.country}}</td><td>{{a.program}}</td><td>{{a.degree}}</td><td class="pending">{{a.payment_status}}</td><td>{{a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "—"}}</td><td>
<form method="POST" action="{{url_for('delete_applicant',applicant_id=a.id)}}" onsubmit="return confirm('Delete this applicant record?')"><input type="hidden" name="_csrf_token" value="{{token}}"><button type="submit">Delete</button></form>
</td></tr>{% endfor %}</tbody></table></div>{% else %}<p class="empty">No applicant registrations yet.</p>{% endif %}


<p><a href="/">Open applicant registration form</a></p></main></body></html>
""", applicants=applicants, legacy_count=legacy_count, token=csrf_token())


@app.route("/admin/visitors")
@admin_required
def admin_visitors():
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    return render_template_string("""
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website Visitors | Global Scholarship Hub</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;margin:0;padding:18px;background:#f2f6fc;color:#17243a}
main{max-width:900px;margin:auto}.heading{background:#1456a0;color:white;padding:22px;border-radius:14px}
.heading h1{margin:0 0 8px;font-size:25px}.count{font-size:18px;font-weight:bold}
.back{display:inline-block;margin:18px 0;padding:13px 17px;background:#1768bd;color:white;text-decoration:none;border-radius:9px;font-weight:bold}
.note{background:#e6f0ff;padding:13px;border-radius:9px;line-height:1.5}
table{width:100%;border-collapse:collapse;background:white;margin-top:16px}
th,td{padding:13px 10px;text-align:left;border-bottom:1px solid #e3eaf3;font-size:14px}
th{background:#1768bd;color:white}.tablebox{overflow-x:auto;border-radius:10px}
@media(max-width:600px){body{padding:10px}.heading h1{font-size:21px}th,td{font-size:12px;padding:11px 8px}}
</style></head><body><main>
<section class="heading"><h1>GLOBAL SCHOLARSHIP HUB</h1><div class="count">{{visitors|length}} WEBSITE VISIT(S) RECORDED</div></section>
<a class="back" href="{{url_for('admin')}}">← Back to Admin Dashboard</a>
<p class="note">This page lists visits to the Applicant Registration page. Visitors are anonymous. We do not collect their names or IP addresses.</p>
{% if visitors %}<div class="tablebox"><table><thead><tr><th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visits</th><th>Page</th></tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%d %b %Y, %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%d %b %Y, %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="note">No visits have been recorded yet.</p>{% endif %}
</main></body></html>
""", visitors=visitors)


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    if not csrf_valid():
        return "Invalid request token.", 400
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/applicant/<int:applicant_id>/delete", methods=["POST"])
@admin_required
def delete_applicant(applicant_id):
    if not csrf_valid():
        return "Invalid request token.", 400
    applicant = db.session.get(ScholarshipApplicant, applicant_id)
    if applicant:
        db.session.delete(applicant)
        db.session.commit()
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=False)


@app.route("/pay")
def wave_payment():
    degree_value = request.args.get("degree", "")
    amounts = {"Bachelor's": "5", "Master's": "8", "PhD": "12"}
    amount = amounts.get(degree_value)
    base_url = os.environ.get("WAVE_PAYMENT_URL", "").strip()
    if not amount:
        return "Please return to the registration form and select your degree level first.", 400
    if not base_url:
        return "Wave payment is not configured. Please contact the site administrator.", 503
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["amount"] = amount
    payment_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return redirect(payment_url, code=302)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    configured_user = os.environ.get("ADMIN_USERNAME", "").strip()
    configured_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not configured_user or not configured_password:
        return "Admin login is not configured.", 503
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh and try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            username_matches = hmac.compare_digest(username.casefold(), configured_user.casefold())
            password_matches = hmac.compare_digest(password, configured_password)
            if username_matches and password_matches:
                session.clear()
                session["is_admin"] = True
                session["_csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin"))
            error = "Incorrect username or password."
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login | Global Scholarship Hub</title>
<style>body{font-family:Arial;background:#edf4fc;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}.card{background:white;padding:30px;border-radius:16px;width:100%;max-width:390px;box-shadow:0 12px 36px #173b641a}.brand-logo{width:100%;margin:0 auto 18px;text-align:center}.brand-logo img{display:block;width:100%;max-height:210px;object-fit:contain;border-radius:12px}h1{color:#1456a0;margin-top:0;text-align:center}label{display:block;margin:16px 0 7px;font-weight:bold}input{width:100%;padding:13px;border:1px solid #ccd7e5;border-radius:8px;box-sizing:border-box;font-size:16px}button{width:100%;padding:13px;margin-top:22px;border:0;border-radius:8px;background:#1768bd;color:white;font-weight:bold;font-size:16px}.error{background:#fff0ef;color:#a12a22;padding:10px;border-radius:8px}a{display:block;text-align:center;margin-top:18px;color:#1768bd}.password-row{position:relative}.password-row input{padding-right:56px}.toggle-password{position:absolute;right:7px;top:50%;transform:translateY(-50%);width:42px;height:42px;margin:0;padding:0;border:0;border-radius:7px;background:transparent;color:#1456a0;font-size:22px;cursor:pointer}.toggle-password:focus{outline:2px solid #2376d2}</style></head>
<body><main class="card"><div class="brand-logo"><img src="/global-scholarship-hub-logo.svg" alt="Global Scholarship Hub logo"></div><h1>Admin Login</h1>{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="hidden" name="_csrf_token" value="{{token}}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>
<label for="password">Password</label><div class="password-row"><input id="password" name="password" type="password" autocomplete="current-password" required><button class="toggle-password" id="toggle-password" type="button" aria-label="Show password" aria-pressed="false" title="Show password">👁</button></div><button type="submit">Log In</button></form><a href="/">Back to registration</a></main><script>
const passwordField=document.getElementById("password");
const togglePassword=document.getElementById("toggle-password");
togglePassword.addEventListener("click",function(){
  const show=passwordField.type==="password";
  passwordField.type=show?"text":"password";
  togglePassword.textContent=show?"🙈":"👁";
  togglePassword.setAttribute("aria-label",show?"Hide password":"Show password");
  togglePassword.setAttribute("title",show?"Hide password":"Show password");
  togglePassword.setAttribute("aria-pressed",String(show));
});
</script></body></html>
""", error=error, token=csrf_token())


@app.route("/admin")
@admin_required
def admin():
    applicants = ScholarshipApplicant.query.order_by(ScholarshipApplicant.created_at.desc()).all()
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    legacy_count = Student.query.count()
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Applicant Dashboard | Global Scholarship Hub</title>
<style>
body{font-family:Arial,sans-serif;margin:0;padding:22px;background:#f5f8fc;color:#17243a}.wrap{max-width:1200px;margin:auto}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{color:#1456a0}
.table-wrap{overflow-x:auto;background:white;border-radius:12px;margin-top:20px}table{width:100%;border-collapse:collapse;min-width:1050px}
th,td{padding:12px;text-align:left;border-bottom:1px solid #e4eaf1;font-size:13px}th{background:#1768bd;color:white}
button{padding:8px 12px;border:0;border-radius:6px;background:#b83232;color:white;cursor:pointer}
.logout{background:#1768bd}a{color:#1768bd}.empty{padding:22px;background:white;border-radius:10px;margin-top:20px}
.pending{color:#996515;font-weight:bold}.meta{color:#64748b;font-size:13px}
</style></head><body><main class="wrap">
<div class="top"><div><h1>Global Scholarship Hub</h1><p><a href="{{url_for('admin_visitors')}}" style="display:inline-block;background:#1768bd;color:white;padding:12px 16px;border-radius:8px;text-decoration:none;font-weight:bold">OPEN WEBSITE VISITORS ({{visitors|length}})</a></p><p class="meta"><strong>{{visitors|length}} page visit(s)</strong> · {{applicants|length}} applicant registration(s)</p></div>
<form method="POST" action="{{url_for('admin_logout')}}"><input type="hidden" name="_csrf_token" value="{{token}}"><button class="logout" type="submit">Log Out</button></form></div>
<h2 style="color:#1456a0;margin-top:34px">Website Visitors</h2>
<p class="meta">Every opening of the Applicant Registration page is listed below. Visitor numbers are anonymous; no IP addresses are collected.</p>
{% if visitors %}<div class="table-wrap"><table style="min-width:720px"><thead><tr>
<th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visit Count</th><th>Last Page</th>
</tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%Y-%m-%d %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%Y-%m-%d %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="empty">No website visits recorded yet. New visits will appear here.</p>{% endif %}
<p class="meta">Older student-registration records retained in the database: {{legacy_count}}.</p>
{% if applicants %}<div class="table-wrap"><table><thead><tr>
<th>GSH Number</th><th>First Name</th><th>Second Name</th><th>Phone</th><th>Country</th><th>Program</th><th>Degree</th><th>Payment</th><th>Registered</th><th>Action</th>
</tr></thead><tbody>
{% for a in applicants %}<tr><td><strong>GSH{{a.id}}</strong></td><td>{{a.first_name}}</td><td>{{a.second_name}}</td><td>{{a.phone}}</td><td>{{a.country}}</td><td>{{a.program}}</td><td>{{a.degree}}</td><td class="pending">{{a.payment_status}}</td><td>{{a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "—"}}</td><td>
<form method="POST" action="{{url_for('delete_applicant',applicant_id=a.id)}}" onsubmit="return confirm('Delete this applicant record?')"><input type="hidden" name="_csrf_token" value="{{token}}"><button type="submit">Delete</button></form>
</td></tr>{% endfor %}</tbody></table></div>{% else %}<p class="empty">No applicant registrations yet.</p>{% endif %}


<p><a href="/">Open applicant registration form</a></p></main></body></html>
""", applicants=applicants, legacy_count=legacy_count, token=csrf_token())


@app.route("/admin/visitors")
@admin_required
def admin_visitors():
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    return render_template_string("""
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website Visitors | Global Scholarship Hub</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;margin:0;padding:18px;background:#f2f6fc;color:#17243a}
main{max-width:900px;margin:auto}.heading{background:#1456a0;color:white;padding:22px;border-radius:14px}
.heading h1{margin:0 0 8px;font-size:25px}.count{font-size:18px;font-weight:bold}
.back{display:inline-block;margin:18px 0;padding:13px 17px;background:#1768bd;color:white;text-decoration:none;border-radius:9px;font-weight:bold}
.note{background:#e6f0ff;padding:13px;border-radius:9px;line-height:1.5}
table{width:100%;border-collapse:collapse;background:white;margin-top:16px}
th,td{padding:13px 10px;text-align:left;border-bottom:1px solid #e3eaf3;font-size:14px}
th{background:#1768bd;color:white}.tablebox{overflow-x:auto;border-radius:10px}
@media(max-width:600px){body{padding:10px}.heading h1{font-size:21px}th,td{font-size:12px;padding:11px 8px}}
</style></head><body><main>
<section class="heading"><h1>GLOBAL SCHOLARSHIP HUB</h1><div class="count">{{visitors|length}} WEBSITE VISIT(S) RECORDED</div></section>
<a class="back" href="{{url_for('admin')}}">← Back to Admin Dashboard</a>
<p class="note">This page lists visits to the Applicant Registration page. Visitors are anonymous. We do not collect their names or IP addresses.</p>
{% if visitors %}<div class="tablebox"><table><thead><tr><th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visits</th><th>Page</th></tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%d %b %Y, %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%d %b %Y, %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="note">No visits have been recorded yet.</p>{% endif %}
</main></body></html>
""", visitors=visitors)


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    if not csrf_valid():
        return "Invalid request token.", 400
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/applicant/<int:applicant_id>/delete", methods=["POST"])
@admin_required
def delete_applicant(applicant_id):
    if not csrf_valid():
        return "Invalid request token.", 400
    applicant = db.session.get(ScholarshipApplicant, applicant_id)
    if applicant:
        db.session.delete(applicant)
        db.session.commit()
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=False)
 + price.toLocaleString('en-US');
  }
  degree.addEventListener('change', updatePayment);
  updatePayment();
})();
</script>
</body></html>
""", message=message, error=error, token=csrf_token(), wave_url=wave_url)


@app.route("/pay")
def wave_payment():
    degree_value = request.args.get("degree", "")
    amounts = {"Bachelor's": "5", "Master's": "8", "PhD": "12"}
    amount = amounts.get(degree_value)
    base_url = os.environ.get("WAVE_PAYMENT_URL", "").strip()
    if not amount:
        return "Please return to the registration form and select your degree level first.", 400
    if not base_url:
        return "Wave payment is not configured. Please contact the site administrator.", 503
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["amount"] = amount
    payment_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return redirect(payment_url, code=302)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    configured_user = os.environ.get("ADMIN_USERNAME", "").strip()
    configured_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not configured_user or not configured_password:
        return "Admin login is not configured.", 503
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh and try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            username_matches = hmac.compare_digest(username.casefold(), configured_user.casefold())
            password_matches = hmac.compare_digest(password, configured_password)
            if username_matches and password_matches:
                session.clear()
                session["is_admin"] = True
                session["_csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin"))
            error = "Incorrect username or password."
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login | Global Scholarship Hub</title>
<style>body{font-family:Arial;background:#edf4fc;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}.card{background:white;padding:30px;border-radius:16px;width:100%;max-width:390px;box-shadow:0 12px 36px #173b641a}.brand-logo{width:100%;margin:0 auto 18px;text-align:center}.brand-logo img{display:block;width:100%;max-height:210px;object-fit:contain;border-radius:12px}h1{color:#1456a0;margin-top:0;text-align:center}label{display:block;margin:16px 0 7px;font-weight:bold}input{width:100%;padding:13px;border:1px solid #ccd7e5;border-radius:8px;box-sizing:border-box;font-size:16px}button{width:100%;padding:13px;margin-top:22px;border:0;border-radius:8px;background:#1768bd;color:white;font-weight:bold;font-size:16px}.error{background:#fff0ef;color:#a12a22;padding:10px;border-radius:8px}a{display:block;text-align:center;margin-top:18px;color:#1768bd}.password-row{position:relative}.password-row input{padding-right:56px}.toggle-password{position:absolute;right:7px;top:50%;transform:translateY(-50%);width:42px;height:42px;margin:0;padding:0;border:0;border-radius:7px;background:transparent;color:#1456a0;font-size:22px;cursor:pointer}.toggle-password:focus{outline:2px solid #2376d2}</style></head>
<body><main class="card"><div class="brand-logo"><img src="/global-scholarship-hub-logo.svg" alt="Global Scholarship Hub logo"></div><h1>Admin Login</h1>{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="hidden" name="_csrf_token" value="{{token}}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>
<label for="password">Password</label><div class="password-row"><input id="password" name="password" type="password" autocomplete="current-password" required><button class="toggle-password" id="toggle-password" type="button" aria-label="Show password" aria-pressed="false" title="Show password">👁</button></div><button type="submit">Log In</button></form><a href="/">Back to registration</a></main><script>
const passwordField=document.getElementById("password");
const togglePassword=document.getElementById("toggle-password");
togglePassword.addEventListener("click",function(){
  const show=passwordField.type==="password";
  passwordField.type=show?"text":"password";
  togglePassword.textContent=show?"🙈":"👁";
  togglePassword.setAttribute("aria-label",show?"Hide password":"Show password");
  togglePassword.setAttribute("title",show?"Hide password":"Show password");
  togglePassword.setAttribute("aria-pressed",String(show));
});
</script></body></html>
""", error=error, token=csrf_token())


@app.route("/admin")
@admin_required
def admin():
    applicants = ScholarshipApplicant.query.order_by(ScholarshipApplicant.created_at.desc()).all()
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    legacy_count = Student.query.count()
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Applicant Dashboard | Global Scholarship Hub</title>
<style>
body{font-family:Arial,sans-serif;margin:0;padding:22px;background:#f5f8fc;color:#17243a}.wrap{max-width:1200px;margin:auto}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{color:#1456a0}
.table-wrap{overflow-x:auto;background:white;border-radius:12px;margin-top:20px}table{width:100%;border-collapse:collapse;min-width:1050px}
th,td{padding:12px;text-align:left;border-bottom:1px solid #e4eaf1;font-size:13px}th{background:#1768bd;color:white}
button{padding:8px 12px;border:0;border-radius:6px;background:#b83232;color:white;cursor:pointer}
.logout{background:#1768bd}a{color:#1768bd}.empty{padding:22px;background:white;border-radius:10px;margin-top:20px}
.pending{color:#996515;font-weight:bold}.meta{color:#64748b;font-size:13px}
</style></head><body><main class="wrap">
<div class="top"><div><h1>Global Scholarship Hub</h1><p><a href="{{url_for('admin_visitors')}}" style="display:inline-block;background:#1768bd;color:white;padding:12px 16px;border-radius:8px;text-decoration:none;font-weight:bold">OPEN WEBSITE VISITORS ({{visitors|length}})</a></p><p class="meta"><strong>{{visitors|length}} page visit(s)</strong> · {{applicants|length}} applicant registration(s)</p></div>
<form method="POST" action="{{url_for('admin_logout')}}"><input type="hidden" name="_csrf_token" value="{{token}}"><button class="logout" type="submit">Log Out</button></form></div>
<h2 style="color:#1456a0;margin-top:34px">Website Visitors</h2>
<p class="meta">Every opening of the Applicant Registration page is listed below. Visitor numbers are anonymous; no IP addresses are collected.</p>
{% if visitors %}<div class="table-wrap"><table style="min-width:720px"><thead><tr>
<th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visit Count</th><th>Last Page</th>
</tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%Y-%m-%d %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%Y-%m-%d %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="empty">No website visits recorded yet. New visits will appear here.</p>{% endif %}
<p class="meta">Older student-registration records retained in the database: {{legacy_count}}.</p>
{% if applicants %}<div class="table-wrap"><table><thead><tr>
<th>GSH Number</th><th>First Name</th><th>Second Name</th><th>Phone</th><th>Country</th><th>Program</th><th>Degree</th><th>Payment</th><th>Registered</th><th>Action</th>
</tr></thead><tbody>
{% for a in applicants %}<tr><td><strong>GSH{{a.id}}</strong></td><td>{{a.first_name}}</td><td>{{a.second_name}}</td><td>{{a.phone}}</td><td>{{a.country}}</td><td>{{a.program}}</td><td>{{a.degree}}</td><td class="pending">{{a.payment_status}}</td><td>{{a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "—"}}</td><td>
<form method="POST" action="{{url_for('delete_applicant',applicant_id=a.id)}}" onsubmit="return confirm('Delete this applicant record?')"><input type="hidden" name="_csrf_token" value="{{token}}"><button type="submit">Delete</button></form>
</td></tr>{% endfor %}</tbody></table></div>{% else %}<p class="empty">No applicant registrations yet.</p>{% endif %}


<p><a href="/">Open applicant registration form</a></p></main></body></html>
""", applicants=applicants, legacy_count=legacy_count, token=csrf_token())


@app.route("/admin/visitors")
@admin_required
def admin_visitors():
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    return render_template_string("""
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website Visitors | Global Scholarship Hub</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;margin:0;padding:18px;background:#f2f6fc;color:#17243a}
main{max-width:900px;margin:auto}.heading{background:#1456a0;color:white;padding:22px;border-radius:14px}
.heading h1{margin:0 0 8px;font-size:25px}.count{font-size:18px;font-weight:bold}
.back{display:inline-block;margin:18px 0;padding:13px 17px;background:#1768bd;color:white;text-decoration:none;border-radius:9px;font-weight:bold}
.note{background:#e6f0ff;padding:13px;border-radius:9px;line-height:1.5}
table{width:100%;border-collapse:collapse;background:white;margin-top:16px}
th,td{padding:13px 10px;text-align:left;border-bottom:1px solid #e3eaf3;font-size:14px}
th{background:#1768bd;color:white}.tablebox{overflow-x:auto;border-radius:10px}
@media(max-width:600px){body{padding:10px}.heading h1{font-size:21px}th,td{font-size:12px;padding:11px 8px}}
</style></head><body><main>
<section class="heading"><h1>GLOBAL SCHOLARSHIP HUB</h1><div class="count">{{visitors|length}} WEBSITE VISIT(S) RECORDED</div></section>
<a class="back" href="{{url_for('admin')}}">← Back to Admin Dashboard</a>
<p class="note">This page lists visits to the Applicant Registration page. Visitors are anonymous. We do not collect their names or IP addresses.</p>
{% if visitors %}<div class="tablebox"><table><thead><tr><th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visits</th><th>Page</th></tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%d %b %Y, %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%d %b %Y, %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="note">No visits have been recorded yet.</p>{% endif %}
</main></body></html>
""", visitors=visitors)


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    if not csrf_valid():
        return "Invalid request token.", 400
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/applicant/<int:applicant_id>/delete", methods=["POST"])
@admin_required
def delete_applicant(applicant_id):
    if not csrf_valid():
        return "Invalid request token.", 400
    applicant = db.session.get(ScholarshipApplicant, applicant_id)
    if applicant:
        db.session.delete(applicant)
        db.session.commit()
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=False)
 + price.toLocaleString('en-US');
  }
  degree.addEventListener('change', updatePayment);
  updatePayment();
})();
</script>
</body></html>
""", message=message, error=error, token=csrf_token(), wave_url=wave_url)


@app.route("/pay")
def wave_payment():
    degree_value = request.args.get("degree", "")
    amounts = {"Bachelor's": "5", "Master's": "8", "PhD": "12"}
    amount = amounts.get(degree_value)
    base_url = os.environ.get("WAVE_PAYMENT_URL", "").strip()
    if not amount:
        return "Please return to the registration form and select your degree level first.", 400
    if not base_url:
        return "Wave payment is not configured. Please contact the site administrator.", 503
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["amount"] = amount
    payment_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return redirect(payment_url, code=302)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    configured_user = os.environ.get("ADMIN_USERNAME", "").strip()
    configured_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not configured_user or not configured_password:
        return "Admin login is not configured.", 503
    if request.method == "POST":
        if not csrf_valid():
            error = "Your session expired. Refresh and try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            username_matches = hmac.compare_digest(username.casefold(), configured_user.casefold())
            password_matches = hmac.compare_digest(password, configured_password)
            if username_matches and password_matches:
                session.clear()
                session["is_admin"] = True
                session["_csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin"))
            error = "Incorrect username or password."
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login | Global Scholarship Hub</title>
<style>body{font-family:Arial;background:#edf4fc;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}.card{background:white;padding:30px;border-radius:16px;width:100%;max-width:390px;box-shadow:0 12px 36px #173b641a}.brand-logo{width:100%;margin:0 auto 18px;text-align:center}.brand-logo img{display:block;width:100%;max-height:210px;object-fit:contain;border-radius:12px}h1{color:#1456a0;margin-top:0;text-align:center}label{display:block;margin:16px 0 7px;font-weight:bold}input{width:100%;padding:13px;border:1px solid #ccd7e5;border-radius:8px;box-sizing:border-box;font-size:16px}button{width:100%;padding:13px;margin-top:22px;border:0;border-radius:8px;background:#1768bd;color:white;font-weight:bold;font-size:16px}.error{background:#fff0ef;color:#a12a22;padding:10px;border-radius:8px}a{display:block;text-align:center;margin-top:18px;color:#1768bd}.password-row{position:relative}.password-row input{padding-right:56px}.toggle-password{position:absolute;right:7px;top:50%;transform:translateY(-50%);width:42px;height:42px;margin:0;padding:0;border:0;border-radius:7px;background:transparent;color:#1456a0;font-size:22px;cursor:pointer}.toggle-password:focus{outline:2px solid #2376d2}</style></head>
<body><main class="card"><div class="brand-logo"><img src="/global-scholarship-hub-logo.svg" alt="Global Scholarship Hub logo"></div><h1>Admin Login</h1>{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="hidden" name="_csrf_token" value="{{token}}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>
<label for="password">Password</label><div class="password-row"><input id="password" name="password" type="password" autocomplete="current-password" required><button class="toggle-password" id="toggle-password" type="button" aria-label="Show password" aria-pressed="false" title="Show password">👁</button></div><button type="submit">Log In</button></form><a href="/">Back to registration</a></main><script>
const passwordField=document.getElementById("password");
const togglePassword=document.getElementById("toggle-password");
togglePassword.addEventListener("click",function(){
  const show=passwordField.type==="password";
  passwordField.type=show?"text":"password";
  togglePassword.textContent=show?"🙈":"👁";
  togglePassword.setAttribute("aria-label",show?"Hide password":"Show password");
  togglePassword.setAttribute("title",show?"Hide password":"Show password");
  togglePassword.setAttribute("aria-pressed",String(show));
});
</script></body></html>
""", error=error, token=csrf_token())


@app.route("/admin")
@admin_required
def admin():
    applicants = ScholarshipApplicant.query.order_by(ScholarshipApplicant.created_at.desc()).all()
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    legacy_count = Student.query.count()
    return render_template_string("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Applicant Dashboard | Global Scholarship Hub</title>
<style>
body{font-family:Arial,sans-serif;margin:0;padding:22px;background:#f5f8fc;color:#17243a}.wrap{max-width:1200px;margin:auto}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{color:#1456a0}
.table-wrap{overflow-x:auto;background:white;border-radius:12px;margin-top:20px}table{width:100%;border-collapse:collapse;min-width:1050px}
th,td{padding:12px;text-align:left;border-bottom:1px solid #e4eaf1;font-size:13px}th{background:#1768bd;color:white}
button{padding:8px 12px;border:0;border-radius:6px;background:#b83232;color:white;cursor:pointer}
.logout{background:#1768bd}a{color:#1768bd}.empty{padding:22px;background:white;border-radius:10px;margin-top:20px}
.pending{color:#996515;font-weight:bold}.meta{color:#64748b;font-size:13px}
</style></head><body><main class="wrap">
<div class="top"><div><h1>Global Scholarship Hub</h1><p><a href="{{url_for('admin_visitors')}}" style="display:inline-block;background:#1768bd;color:white;padding:12px 16px;border-radius:8px;text-decoration:none;font-weight:bold">OPEN WEBSITE VISITORS ({{visitors|length}})</a></p><p class="meta"><strong>{{visitors|length}} page visit(s)</strong> · {{applicants|length}} applicant registration(s)</p></div>
<form method="POST" action="{{url_for('admin_logout')}}"><input type="hidden" name="_csrf_token" value="{{token}}"><button class="logout" type="submit">Log Out</button></form></div>
<h2 style="color:#1456a0;margin-top:34px">Website Visitors</h2>
<p class="meta">Every opening of the Applicant Registration page is listed below. Visitor numbers are anonymous; no IP addresses are collected.</p>
{% if visitors %}<div class="table-wrap"><table style="min-width:720px"><thead><tr>
<th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visit Count</th><th>Last Page</th>
</tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%Y-%m-%d %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%Y-%m-%d %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="empty">No website visits recorded yet. New visits will appear here.</p>{% endif %}
<p class="meta">Older student-registration records retained in the database: {{legacy_count}}.</p>
{% if applicants %}<div class="table-wrap"><table><thead><tr>
<th>GSH Number</th><th>First Name</th><th>Second Name</th><th>Phone</th><th>Country</th><th>Program</th><th>Degree</th><th>Payment</th><th>Registered</th><th>Action</th>
</tr></thead><tbody>
{% for a in applicants %}<tr><td><strong>GSH{{a.id}}</strong></td><td>{{a.first_name}}</td><td>{{a.second_name}}</td><td>{{a.phone}}</td><td>{{a.country}}</td><td>{{a.program}}</td><td>{{a.degree}}</td><td class="pending">{{a.payment_status}}</td><td>{{a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "—"}}</td><td>
<form method="POST" action="{{url_for('delete_applicant',applicant_id=a.id)}}" onsubmit="return confirm('Delete this applicant record?')"><input type="hidden" name="_csrf_token" value="{{token}}"><button type="submit">Delete</button></form>
</td></tr>{% endfor %}</tbody></table></div>{% else %}<p class="empty">No applicant registrations yet.</p>{% endif %}


<p><a href="/">Open applicant registration form</a></p></main></body></html>
""", applicants=applicants, legacy_count=legacy_count, token=csrf_token())


@app.route("/admin/visitors")
@admin_required
def admin_visitors():
    visitors = WebsiteVisitor.query.order_by(WebsiteVisitor.last_visited_at.desc()).all()
    return render_template_string("""
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website Visitors | Global Scholarship Hub</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;margin:0;padding:18px;background:#f2f6fc;color:#17243a}
main{max-width:900px;margin:auto}.heading{background:#1456a0;color:white;padding:22px;border-radius:14px}
.heading h1{margin:0 0 8px;font-size:25px}.count{font-size:18px;font-weight:bold}
.back{display:inline-block;margin:18px 0;padding:13px 17px;background:#1768bd;color:white;text-decoration:none;border-radius:9px;font-weight:bold}
.note{background:#e6f0ff;padding:13px;border-radius:9px;line-height:1.5}
table{width:100%;border-collapse:collapse;background:white;margin-top:16px}
th,td{padding:13px 10px;text-align:left;border-bottom:1px solid #e3eaf3;font-size:14px}
th{background:#1768bd;color:white}.tablebox{overflow-x:auto;border-radius:10px}
@media(max-width:600px){body{padding:10px}.heading h1{font-size:21px}th,td{font-size:12px;padding:11px 8px}}
</style></head><body><main>
<section class="heading"><h1>GLOBAL SCHOLARSHIP HUB</h1><div class="count">{{visitors|length}} WEBSITE VISIT(S) RECORDED</div></section>
<a class="back" href="{{url_for('admin')}}">← Back to Admin Dashboard</a>
<p class="note">This page lists visits to the Applicant Registration page. Visitors are anonymous. We do not collect their names or IP addresses.</p>
{% if visitors %}<div class="tablebox"><table><thead><tr><th>Visitor</th><th>First Visited</th><th>Last Visited</th><th>Visits</th><th>Page</th></tr></thead><tbody>
{% for v in visitors %}<tr><td>Visitor #{{v.id}}</td><td>{{v.first_visited_at.strftime("%d %b %Y, %H:%M") if v.first_visited_at else "—"}}</td><td>{{v.last_visited_at.strftime("%d %b %Y, %H:%M") if v.last_visited_at else "—"}}</td><td>{{v.visit_count}}</td><td>{{v.last_path}}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class="note">No visits have been recorded yet.</p>{% endif %}
</main></body></html>
""", visitors=visitors)


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    if not csrf_valid():
        return "Invalid request token.", 400
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/applicant/<int:applicant_id>/delete", methods=["POST"])
@admin_required
def delete_applicant(applicant_id):
    if not csrf_valid():
        return "Invalid request token.", 400
    applicant = db.session.get(ScholarshipApplicant, applicant_id)
    if applicant:
        db.session.delete(applicant)
        db.session.commit()
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=False)
