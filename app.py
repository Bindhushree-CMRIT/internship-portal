import os, re, time

from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///portal.db"
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

DOMAINS = ["Web Development", "AI / Machine Learning", "Data Science", "Mobile Apps",
           "IoT / Embedded", "Cybersecurity", "Cloud / DevOps", "UI / UX Design"]
ALLOWED = {"png", "jpg", "jpeg", "pdf"}
FREE_MAIL = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"]


# ---------- DATABASE TABLES ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student / company / admin
    company = db.relationship("Company", backref="user", uselist=False)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    name = db.Column(db.String(150))
    cin = db.Column(db.String(30))
    gst = db.Column(db.String(30))
    website = db.Column(db.String(150))
    sign_name = db.Column(db.String(100))
    sign_role = db.Column(db.String(100))
    reg_doc = db.Column(db.String(200), default="")
    sign_doc = db.Column(db.String(200), default="")
    status = db.Column(db.String(20), default="pending")  # pending/verified/rejected
    reason = db.Column(db.String(300), default="")
    jobs = db.relationship("Internship", backref="company")


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(150))
    description = db.Column(db.Text)
    domain = db.Column(db.String(60))
    link = db.Column(db.String(300), default="")
    file = db.Column(db.String(200), default="")


class Internship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"))
    title = db.Column(db.String(150))
    domain = db.Column(db.String(60))
    duration = db.Column(db.String(60))
    description = db.Column(db.Text)


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    internship_id = db.Column(db.Integer, db.ForeignKey("internship.id"))
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"))
    status = db.Column(db.String(20), default="applied")  # applied/shortlisted/selected/rejected
    reason = db.Column(db.String(300), default="")
    student = db.relationship("User")
    internship = db.relationship("Internship")
    project = db.relationship("Project")


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ---------- HELPERS ----------
def role_required(role):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role:
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco


def save_file(f):
    if f and f.filename:
        ext = f.filename.rsplit(".", 1)[-1].lower()
        if ext in ALLOWED:
            name = f"{int(time.time())}_{secure_filename(f.filename)}"
            f.save(os.path.join(app.config["UPLOAD_FOLDER"], name))
            return name
    return ""


def run_checks(c):
    """Automatic verification checks. Returns list of (label, passed)."""
    site = (c.website or "").lower().replace("https://", "").replace("http://", "")
    site = site.replace("www.", "").split("/")[0]
    domain = c.user.email.split("@")[1].lower()
    return [
        ("Company name provided", len(c.name or "") > 2),
        ("CIN format is valid", bool(re.fullmatch(r"[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}", c.cin or ""))),
        ("GSTIN format is valid", bool(re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]", c.gst or ""))),
        ("Official email (not Gmail/Yahoo etc.)", domain not in FREE_MAIL),
        ("Email domain matches website", domain == site),
        ("Registration certificate uploaded", bool(c.reg_doc)),
        ("Signatory named + ID/authorization uploaded", bool(c.sign_name) and bool(c.sign_doc)),
    ]


app.jinja_env.globals["run_checks"] = run_checks
app.context_processor(lambda: dict(DOMAINS=DOMAINS))


def verified_company():
    c = current_user.company
    if not c or c.status != "verified":
        flash("Your company must be verified first.", "error")
        return None
    return c


# ---------- PUBLIC PAGES ----------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]
        if role not in ("student", "company"):
            abort(400)
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif User.query.filter_by(email=email).first():
            flash("That email is already registered.", "error")
        else:
            u = User(email=email, password_hash=generate_password_hash(password), role=role)
            db.session.add(u)
            db.session.commit()
            login_user(u)
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(email=request.form["email"].strip().lower()).first()
        if u and check_password_hash(u.password_hash, request.form["password"]):
            login_user(u)
            return redirect(url_for("dashboard"))
        flash("Wrong email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for({"company": "company_dashboard", "student": "student_dashboard",
                             "admin": "admin"}[current_user.role]))


@app.route("/files/<name>")
@login_required
def files(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


# ---------- COMPANY ----------
@app.route("/company")
@role_required("company")
def company_dashboard():
    c = current_user.company
    if not c:
        return redirect(url_for("company_register"))
    return render_template("company_dashboard.html", c=c)


@app.route("/company/register", methods=["GET", "POST"])
@role_required("company")
def company_register():
    if current_user.company:
        return redirect(url_for("company_dashboard"))
    if request.method == "POST":
        f = request.form
        c = Company(user_id=current_user.id, name=f["name"].strip(),
                    cin=f["cin"].strip().upper(), gst=f["gst"].strip().upper(),
                    website=f["website"].strip(), sign_name=f["sign_name"].strip(),
                    sign_role=f["sign_role"].strip(),
                    reg_doc=save_file(request.files.get("reg_doc")),
                    sign_doc=save_file(request.files.get("sign_doc")))
        db.session.add(c)
        db.session.commit()
        flash("Submitted for verification.", "ok")
        return redirect(url_for("company_dashboard"))
    return render_template("company_register.html")


@app.route("/company/post", methods=["GET", "POST"])
@role_required("company")
def post_job():
    c = verified_company()
    if not c:
        return redirect(url_for("company_dashboard"))
    if request.method == "POST":
        f = request.form
        db.session.add(Internship(company_id=c.id, title=f["title"], domain=f["domain"],
                                  duration=f["duration"], description=f["description"]))
        db.session.commit()
        flash("Internship published.", "ok")
        return redirect(url_for("company_dashboard"))
    return render_template("post_job.html")


@app.route("/company/applicants")
@role_required("company")
def applicants():
    c = verified_company()
    if not c:
        return redirect(url_for("company_dashboard"))
    apps = (Application.query.join(Internship)
            .filter(Internship.company_id == c.id).order_by(Application.id.desc()).all())
    return render_template("applicants.html", apps=apps)


@app.route("/application/<int:aid>/<status>", methods=["POST"])
@role_required("company")
def update_application(aid, status):
    a = db.session.get(Application, aid) or abort(404)
    if a.internship.company.user_id != current_user.id:
        abort(403)
    if status not in ("shortlisted", "selected", "rejected"):
        abort(400)
    reason = request.form.get("reason", "").strip()
    if status == "rejected" and not reason:
        flash("Please give a reason so the student can improve.", "error")
        return redirect(url_for("applicants"))
    a.status, a.reason = status, reason
    db.session.commit()
    return redirect(url_for("applicants"))


# ---------- STUDENT ----------
@app.route("/student", methods=["GET", "POST"])
@role_required("student")
def student_dashboard():
    if request.method == "POST":
        f = request.form
        link = f.get("link", "").strip()
        if link and not link.startswith(("http://", "https://")):
            link = ""
        db.session.add(Project(student_id=current_user.id, title=f["title"], domain=f["domain"],
                               description=f["description"], link=link,
                               file=save_file(request.files.get("file"))))
        db.session.commit()
        flash("Project saved.", "ok")
        return redirect(url_for("student_dashboard"))
    projects = Project.query.filter_by(student_id=current_user.id).all()
    return render_template("student_dashboard.html", projects=projects)


@app.route("/jobs")
@role_required("student")
def jobs():
    items = Internship.query.join(Company).filter(Company.status == "verified").all()
    projects = Project.query.filter_by(student_id=current_user.id).all()
    applied = {a.internship_id: a for a in Application.query.filter_by(student_id=current_user.id)}
    return render_template("jobs.html", jobs=items, projects=projects, applied=applied)


@app.route("/apply/<int:job_id>", methods=["POST"])
@role_required("student")
def apply(job_id):
    job = db.session.get(Internship, job_id) or abort(404)
    if job.company.status != "verified":
        abort(403)
    p = db.session.get(Project, int(request.form.get("project_id", 0)))
    if not p or p.student_id != current_user.id or p.domain != job.domain:
        flash("You need a project in this internship's domain.", "error")
    elif Application.query.filter_by(student_id=current_user.id, internship_id=job.id).first():
        flash("You already applied.", "error")
    else:
        db.session.add(Application(student_id=current_user.id, internship_id=job.id, project_id=p.id))
        db.session.commit()
        flash("Applied successfully!", "ok")
    return redirect(url_for("jobs"))


@app.route("/my-applications")
@role_required("student")
def my_applications():
    apps = Application.query.filter_by(student_id=current_user.id).order_by(Application.id.desc()).all()
    return render_template("my_applications.html", apps=apps)


# ---------- ADMIN ----------
@app.route("/admin")
@role_required("admin")
def admin():
    companies = Company.query.order_by(Company.id.desc()).all()
    return render_template("admin.html", companies=companies)


@app.route("/admin/company/<int:cid>/<action>", methods=["POST"])
@role_required("admin")
def admin_action(cid, action):
    c = db.session.get(Company, cid) or abort(404)
    reason = request.form.get("reason", "").strip()
    if action == "approve":
        c.status, c.reason = "verified", ""
    elif action == "reject":
        if not reason:
            flash("Give a reason for rejection.", "error")
            return redirect(url_for("admin"))
        c.status, c.reason = "rejected", reason
    else:
        abort(400)
    db.session.commit()
    return redirect(url_for("admin"))


# ---------- START ----------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        db.session.add(User(email="admin@portal.com", role="admin",
                            password_hash=generate_password_hash("admin123")))
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)