from flask import Flask, render_template, redirect, url_for, request, flash, session
from models import db, User, Waitlist, Opportunity, Application, create_admin_user, init_db
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from datetime import datetime
import os
from functools import wraps
from dotenv import load_dotenv

# Import admin blueprint
from admin_routes import admin_bp
from decorators import admin_required, role_required

load_dotenv()

# Allow HTTP for OAuth (ONLY for localhost)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("CLIENT_SECRET")

# Initialize database
db.init_app(app=app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login first."

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ================= REGISTER ADMIN BLUEPRINT =================

app.register_blueprint(admin_bp)


# ================= CONTEXT PROCESSORS =================

@app.context_processor
def inject_admin_stats():
    """Inject admin statistics into all templates"""
    if current_user.is_authenticated and current_user.role == 'admin':
        pending_opportunities = Opportunity.query.filter_by(status='pending', deleted_at=None).count()
        from models import Report
        pending_reports = Report.query.filter_by(status='pending').count()
        
        return dict(
            pending_opportunities=pending_opportunities,
            pending_reports=pending_reports
        )
    return dict()


# ================= GOOGLE OAUTH SETUP =================

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_to="google_login_callback",
    reprompt_consent=True
)

app.register_blueprint(google_bp, url_prefix="/login")


# ================= GOOGLE CALLBACK ROUTE =================

@app.route("/google_callback")
def google_login_callback():
    """Handle Google OAuth callback"""
    
    print("=== GOOGLE CALLBACK ROUTE CALLED ===")
    
    if not google.authorized:
        print("❌ Google not authorized")
        flash("Google authorization failed. Please try again.")
        return redirect(url_for("login"))

    try:
        resp = google.get("/oauth2/v2/userinfo")
        print(f"📡 Google API response status: {resp.status_code}")
        
        if not resp.ok:
            print(f"❌ Failed to get user info: {resp.text}")
            flash("Failed to get user information from Google.")
            return redirect(url_for("login"))

        info = resp.json()
        print(f"✅ User info received: {info}")

        email = info.get("email")
        name = info.get("name")
        
        if not email:
            print("❌ Email not provided by Google")
            flash("Email not provided by Google.")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()

        if not user:
            print(f"🆕 New user detected: {email}")
            session['google_user_name'] = name
            session['google_user_email'] = email
            flash("Please select your role to complete registration.")
            return redirect(url_for("select_role_google"))
        
        else:
            print(f"👤 Existing user found: {email}")
            login_user(user, remember=True)
            print(f"✅ User logged in: {user.email} ({user.role})")

            flash(f"Welcome back, {user.name}!")
            
            # Redirect based on role
            if user.role == "student":
                return redirect(url_for("student_dashboard"))
            elif user.role == "company":
                return redirect(url_for("company_dashboard"))
            elif user.role == "admin":
                return redirect(url_for("admin.dashboard"))
            else:
                return redirect(url_for("home"))
        
    except Exception as e:
        print(f"❌ Error in google_callback: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"An error occurred during login: {str(e)}")
        return redirect(url_for("login"))


# ================= ROLE SELECTION FOR GOOGLE SIGNUP =================

@app.route("/select_role_google", methods=["GET", "POST"])
def select_role_google():
    """Allow new Google users to select their role"""
    
    if 'google_user_email' not in session:
        flash("Session expired. Please login again.")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        role = request.form.get("role")
        
        if not role or role not in ["student", "company"]:
            flash("Please select a valid role.")
            return redirect(url_for("select_role_google"))
        
        name = session.get('google_user_name')
        email = session.get('google_user_email')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Account already exists. Logging you in.")
            login_user(existing_user, remember=True)
            session.pop('google_user_name', None)
            session.pop('google_user_email', None)
            return redirect(url_for("home"))
        
        try:
            new_user = User(
                name=name,
                email=email,
                password=generate_password_hash("google_oauth_" + email),
                role=role
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            print(f"✅ New user created: {email} as {role}")
            
            session.pop('google_user_name', None)
            session.pop('google_user_email', None)
            
            login_user(new_user, remember=True)
            
            flash(f"Welcome to TrustNex, {new_user.name}!")
            
            if role == "student":
                return redirect(url_for("student_dashboard"))
            elif role == "company":
                return redirect(url_for("company_dashboard"))
            else:
                return redirect(url_for("home"))
                
        except Exception as e:
            print(f"❌ Error creating user: {str(e)}")
            import traceback
            traceback.print_exc()
            flash("Error creating account. Please try again.")
            return redirect(url_for("select_role_google"))
    
    email = session.get('google_user_email')
    name = session.get('google_user_name')
    return render_template("select_role_google.html", email=email, name=name)


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

@app.route("/apply/<int:op_id>")
@role_required("student")
def apply(op_id):

    if current_user.role != "student":
        flash("Only students can apply.")
        return redirect(url_for("opportunities"))

    google_form_link = "https://forms.gle/YOUR_GOOGLE_FORM_LINK"

    return redirect(google_form_link)

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            if user.role != role:
                flash("Incorrect role selected.")
                return redirect(url_for("login"))

            # Check if account is suspended
            if user.is_suspended:
                flash("Your account has been suspended. Please contact support.", "danger")
                return redirect(url_for("login"))

            login_user(user)
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash(f"Logged in successfully as {user.email}!")

            if user.role == "student":
                return redirect(url_for("student_dashboard"))
            elif user.role == "company":
                return redirect(url_for("company_dashboard"))
            elif user.role == "admin":
                return redirect(url_for("admin.dashboard"))

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

        flash("Thanks! We'll notify you soon.")
        return redirect(url_for("early_access"))

    return render_template("early_access.html")


# ================= OPPORTUNITIES =================

@app.route("/opportunities")
def opportunities():
    # Only show approved opportunities to non-admins
    if current_user.is_authenticated and current_user.role == 'admin':
        all_ops = Opportunity.query.filter_by(deleted_at=None).all()
    else:
        all_ops = Opportunity.query.filter_by(
            status='approved',
            is_active=True,
            deleted_at=None
        ).all()

    return render_template(
        "opportunities.html",
        opportunities=all_ops
    )

# ================= POST OPPORTUNITY =================

@app.route("/post-opportunity", methods=["GET", "POST"])
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
            contact=contact,
            status='pending'  # All new opportunities start as pending
        )

        db.session.add(new_opportunity)
        db.session.commit()

        flash("Opportunity Posted Successfully! It will be reviewed by our admin team.", "success")

        return redirect(url_for("company_dashboard"))

    return render_template("post_opportunity.html")

@app.route("/student-dashboard")
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
@role_required("company")
def company_dashboard():

    if current_user.role != "company":
        flash("Access denied.")
        return redirect(url_for("home"))

    my_opportunities = Opportunity.query.filter_by(
        user_id=current_user.id
    ).all()
    
    total_applications = sum(len(op.applications) for op in my_opportunities)

    return render_template(
        "company_dashboard.html",
        opportunities=my_opportunities,
        total_applications=total_applications
    )

@app.route("/dashboard")
@login_required
def dashboard():

    my_applications = Application.query.filter_by(
        user_id=current_user.id
    ).all()

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
    flash("You have been logged out successfully.")
    return redirect(url_for("home"))


# ================= DATABASE INITIALIZATION =================

if __name__ == "__main__":
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created")
        
        # Create default admin user (only if doesn't exist)
        admin_email = "admin@trustnex.com"
        admin = User.query.filter_by(email=admin_email).first()
        
        if not admin:
            admin = create_admin_user(
                email=admin_email,
                password="adminpass123",  # CHANGE THIS IN PRODUCTION!
                name="Admin User"
            )
            print(f"✅ Default admin created: {admin_email} / adminpass123")
        else:
            print(f"ℹ️  Admin user already exists: {admin_email}")
    
    app.run(debug=True)