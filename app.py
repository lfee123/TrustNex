from flask import Flask, render_template, redirect, url_for, request, flash
from models import db, User, Waitlist, Opportunity, Application
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
import os
from functools import wraps
from dotenv import loadenv

loadenv()
# Allow HTTP for OAuth (ONLY for localhost)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("CLIENT_SECRET")

db.init_app(app=app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login first."

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================= RBAC DECORATOR =================

def role_required(role):

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):

            if not current_user.is_authenticated:
                flash("Please login first.")
                return redirect(url_for("login"))

            if current_user.role != role:
                flash("Access denied.")
                return redirect(url_for("home"))

            return func(*args, **kwargs)

        return wrapper

    return decorator
# ================= DATABASE MODEL =================


# ================= GOOGLE OAUTH =================

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    reprompt_select_account=True
)


# Override the authorized route
@google_bp.route("/authorized")
def google_authorized():
    print("=== GOOGLE AUTHORIZED ROUTE CALLED ===")
    
    if not google.authorized:
        print("Google not authorized")
        return redirect(url_for("login"))

    try:
        # Get user info from Google
        resp = google.get("/oauth2/v2/userinfo")
        print(f"Google API response status: {resp.status_code}")
        
        if not resp.ok:
            print(f"Failed to get user info from Google: {resp.text}")
            flash("Failed to get user info from Google.")
            return redirect(url_for("login"))

        info = resp.json()
        print(f"User info from Google: {info}")

        email = info.get("email")
        name = info.get("name")
        
        if not email:
            print("Email not provided by Google")
            flash("Email not provided by Google")
            return redirect(url_for("login"))

        # Check if user exists
        user = User.query.filter_by(email=email).first()

        if not user:
            print(f"Creating new user: {email}")
            user = User(
                name=name,
                email=email,
                password="google_login"
            )
            db.session.add(user)
            db.session.commit()
            print(f"User created successfully with ID: {user.id}")
        else:
            print(f"User already exists: {email}")

        # Log in the user
        login_user(user, remember=True)
        print(f"User logged in: {user.email}")

        flash("Logged in with Google successfully!")
        
        return redirect(url_for("dashboard"))
        
    except Exception as e:
        print(f"Error in google_authorized: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"Error: {str(e)}")
        return redirect(url_for("login"))


# ✅ REGISTER BLUEPRINT
app.register_blueprint(google_bp, url_prefix="/login")

# ================= NORMAL ROUTES =================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/students")
def students():
    return render_template("students.html")


@app.route("/companies")
def companies():
    return render_template("companies.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful! Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")

# =================APPLY==================

# @app.route("/apply/<int:op_id>", methods=["GET", "POST"])
# @login_required
# def apply(op_id):

#     opportunity = Opportunity.query.get_or_404(op_id)

#     if request.method == "POST":

#         message = request.form.get("message")

#         # Prevent duplicate apply
#         existing = Application.query.filter_by(
#             user_id=current_user.id,
#             opportunity_id=op_id
#         ).first()

#         if existing:
#             flash("You already applied to this opportunity.")
#             return redirect(url_for("opportunities"))

#         new_application = Application(
#             user_id=current_user.id,
#             opportunity_id=op_id,
#             message=message
#         )

#         db.session.add(new_application)
#         db.session.commit()

#         flash("Application Submitted Successfully!")

#         return redirect(url_for("opportunities"))

#     return render_template(
#         "apply.html",
#         opportunity=opportunity
#     )

# ============APPLY2=============

@app.route("/apply/<int:op_id>")
# @login_required
@role_required("student")
def apply(op_id):

    if current_user.role != "student":
        flash("Only students can apply.")
        return redirect(url_for("opportunities"))

    # 🔴 Put your Google Form link here
    google_form_link = "https://forms.gle/YOUR_GOOGLE_FORM_LINK"

    return redirect(google_form_link)

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")
        user = User.query.filter_by(email=email).first()
        # Check credentials
        if user and check_password_hash(user.password, password):
            #Role mismatch
            if user.role != role:
                flash("Incorrect role selected.")
                return redirect(url_for("login"))

            # ✅ Login user
            login_user(user)

            # 🔁 Auto redirect based on role
            if user.role == "student":
                return redirect(url_for("student_dashboard"))

            elif user.role == "company":
                return redirect(url_for("company_dashboard"))

            elif user.role == "admin":
                return redirect(url_for("admin_panel"))

        # ❌ Invalid credentials
        flash("Invalid Email or Password.")
        return redirect(url_for("login"))

    return render_template("login.html")

# ================= EARLY ACCESS =================

@app.route("/early-access", methods=["GET", "POST"])
def early_access():

    if request.method == "POST":

        name = request.form.get("name")
        email = request.form.get("email")
        role = request.form.get("role")
        org = request.form.get("org")

        # Check duplicate email
        existing = Waitlist.query.filter_by(email=email).first()
        if existing:
            flash("You are already on the waitlist!")
            return redirect(url_for("early_access"))

        new_user = Waitlist(
            name=name,
            email=email,
            role=role,
            org_name=org
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Thanks! We’ll notify you soon.")
        return redirect(url_for("early_access"))

    return render_template("early_access.html")


# ================= OPPORTUNITIES =================

@app.route("/opportunities")
def opportunities():

    all_ops = Opportunity.query.all()

    return render_template(
        "opportunities.html",
        opportunities=all_ops
    )

# ================= POST OPPORTUNITY =================

@app.route("/post-opportunity", methods=["GET", "POST"])
# @login_required
@role_required("company")
def post_opportunity():

    if request.method == "POST":

        title = request.form.get("title")
        opp_type = request.form.get("type")
        desc = request.form.get("description")
        skills = request.form.get("skills")
        task = request.form.get("task")
        duration = request.form.get("duration")
        paid = request.form.get("paid")
        contact = request.form.get("contact")

        new_opportunity = Opportunity(

            user_id=current_user.id,

            title=title,
            opportunity_type=opp_type,
            description=desc,
            skills=skills,
            task=task,
            duration=duration,
            paid=paid,
            contact=contact
        )

        db.session.add(new_opportunity)
        db.session.commit()

        flash("Opportunity Posted Successfully!")

        return redirect(url_for("dashboard"))

    return render_template("post_opportunity.html")

@app.route("/student-dashboard")
# @login_required
@role_required("student")
def student_dashboard():

    if current_user.role != "student":
        flash("Access denied.")
        return redirect(url_for("home"))

    my_applications = Application.query.filter_by(
        user_id=current_user.id
    ).all()

    return render_template(
        "student_dashboard.html",
        applications=my_applications
    )


@app.route("/company-dashboard")
# @login_required
@role_required("company")
def company_dashboard():

    if current_user.role != "company":
        flash("Access denied.")
        return redirect(url_for("home"))

    my_opportunities = Opportunity.query.filter_by(
        user_id=current_user.id
    ).all()

    return render_template(
        "company_dashboard.html",
        opportunities=my_opportunities
    )

@app.route("/dashboard")
@login_required
def dashboard():

    # Applications by this student
    my_applications = Application.query.filter_by(
        user_id=current_user.id
    ).all()

    # Opportunities posted by this company
    my_opportunities = Opportunity.query.filter_by(
        user_id=current_user.id
    ).all()

    return render_template(
        "dashboard.html",
        applications=my_applications,
        opportunities=my_opportunities
    )

@app.route("/company/opportunity/<int:op_id>")
@login_required
def view_applicants(op_id):

    opportunity = Opportunity.query.get_or_404(op_id)

    # Security check
    if opportunity.user_id != current_user.id:
        flash("Unauthorized access.")
        return redirect(url_for("dashboard"))

    return render_template(
        "view_applicants.html",
        opportunity=opportunity
    )

@app.route("/approve/<int:app_id>")
@login_required
def approve(app_id):

    application = Application.query.get_or_404(app_id)

    if application.opportunity.user_id != current_user.id:
        flash("Unauthorized.")
        return redirect(url_for("dashboard"))

    application.status = "Approved"
    db.session.commit()

    flash("Application Approved.")

    return redirect(request.referrer)

@app.route("/admin")
# @login_required
@role_required("admin")
def admin_panel():

    if current_user.email != "admin@trustnex.com":
        flash("Admin access only.")
        return redirect(url_for("home"))

    users = User.query.all()
    opportunities = Opportunity.query.all()
    applications = Application.query.all()

    return render_template(
        "admin.html",
        users=users,
        opportunities=opportunities,
        applications=applications
    )

@app.route("/reject/<int:app_id>")
@login_required
def reject(app_id):

    application = Application.query.get_or_404(app_id)

    if application.opportunity.user_id != current_user.id:
        flash("Unauthorized.")
        return redirect(url_for("dashboard"))

    application.status = "Rejected"
    db.session.commit()

    flash("Application Rejected.")

    return redirect(request.referrer)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    if request.method == "POST":

        current_user.name = request.form.get("name")
        current_user.email = request.form.get("email")

        db.session.commit()

        flash("Profile Updated Successfully!")
        return redirect(url_for("profile"))

    return render_template("profile.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)