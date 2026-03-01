from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import func

db = SQLAlchemy()


# ================= USER MODEL =================

class User(UserMixin, db.Model):
    """
    Core user model with role-based access control
    Supports: students, companies, admins
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')  # student / company / admin
    
    # Status flags
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    
    # Company-specific fields
    company_name = db.Column(db.String(150))
    company_description = db.Column(db.Text)
    
    # Soft delete
    deleted_at = db.Column(db.DateTime)
    
    # Relationships
    opportunities = db.relationship("Opportunity", back_populates="user", foreign_keys="Opportunity.user_id" , lazy='dynamic')
    applications = db.relationship("Application", back_populates="user", lazy='dynamic')
    reports_made = db.relationship("Report", foreign_keys='Report.reporter_id', back_populates="reporter", lazy='dynamic')
    reports_received = db.relationship("Report", foreign_keys='Report.reported_id', back_populates="reported_user", lazy='dynamic')

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"
    
    @property
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    @property
    def is_company(self):
        """Check if user is a company"""
        return self.role == 'company'
    
    @property
    def is_student(self):
        """Check if user is a student"""
        return self.role == 'student'
    
    def soft_delete(self):
        """Soft delete user instead of hard delete"""
        self.deleted_at = datetime.utcnow()
        self.is_active = False
        db.session.commit()
    
    def activate(self):
        """Activate user account"""
        self.is_active = True
        self.is_suspended = False
        self.deleted_at = None
        db.session.commit()
    
    def suspend(self):
        """Suspend user account"""
        self.is_suspended = True
        self.is_active = False
        db.session.commit()


# ================= WAITLIST =================

class Waitlist(db.Model):
    """Early access waitlist"""
    __tablename__ = "waitlist"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(50))  # student / company
    org_name = db.Column(db.String(150))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<Waitlist {self.email}>"


# ================= OPPORTUNITY MODEL =================

class Opportunity(db.Model):
    """
    Job/Internship/Challenge opportunities
    Includes moderation workflow
    """
    __tablename__ = "opportunities"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    opportunity_type = db.Column(db.String(50))  # internship/job/challenge
    description = db.Column(db.Text)
    skills = db.Column(db.String(300))
    task = db.Column(db.Text)
    duration = db.Column(db.String(100))
    paid = db.Column(db.String(20))  # paid/unpaid
    contact = db.Column(db.String(150))
    
    # Moderation fields
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending/approved/rejected/flagged
    is_featured = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    
    # Soft delete
    deleted_at = db.Column(db.DateTime)
    
    # Statistics
    views_count = db.Column(db.Integer, default=0)
    applications_count = db.Column(db.Integer, default=0)
    
    # Relationships
    user = db.relationship("User", back_populates="opportunities", foreign_keys=[user_id])
    applications = db.relationship("Application", back_populates="opportunity", lazy='dynamic')
    reports = db.relationship("Report", back_populates="opportunity", lazy='dynamic')

    def __repr__(self):
        return f"<Opportunity {self.title} ({self.status})>"
    
    def approve(self, admin_id):
        """Approve opportunity"""
        self.status = 'approved'
        self.approved_at = datetime.utcnow()
        self.approved_by = admin_id
        db.session.commit()
    
    def reject(self):
        """Reject opportunity"""
        self.status = 'rejected'
        db.session.commit()
    
    def flag(self):
        """Flag opportunity for review"""
        self.status = 'flagged'
        db.session.commit()
    
    def soft_delete(self):
        """Soft delete opportunity"""
        self.deleted_at = datetime.utcnow()
        self.is_active = False
        db.session.commit()


# ================= APPLICATION MODEL =================

class Application(db.Model):
    """
    Student applications to opportunities
    Tracks application lifecycle
    """
    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    opportunity_id = db.Column(db.Integer, db.ForeignKey("opportunities.id"), nullable=False)

    status = db.Column(db.String(20), default="pending", nullable=False)  # pending/approved/rejected/spam
    message = db.Column(db.Text)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    reviewed_at = db.Column(db.DateTime)
    
    # Spam detection
    is_spam = db.Column(db.Boolean, default=False)
    spam_score = db.Column(db.Float, default=0.0)
    
    # Relationships
    user = db.relationship("User", back_populates="applications")
    opportunity = db.relationship("Opportunity", back_populates="applications")

    def __repr__(self):
        return f"<Application User:{self.user_id} -> Opp:{self.opportunity_id} ({self.status})>"
    
    def mark_as_spam(self):
        """Mark application as spam"""
        self.is_spam = True
        self.status = 'spam'
        db.session.commit()


# ================= REPORT MODEL =================

class Report(db.Model):
    """
    User/Company reporting system
    Allows users to flag inappropriate content or behavior
    """
    __tablename__ = "reports"
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Reporter information
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    
    # Reported entity
    reported_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # If reporting a user
    opportunity_id = db.Column(db.Integer, db.ForeignKey("opportunities.id"))  # If reporting an opportunity
    
    # Report details
    report_type = db.Column(db.String(50), nullable=False)  # user/opportunity/application
    reason = db.Column(db.String(100), nullable=False)  # spam/inappropriate/fraud/scam/harassment
    description = db.Column(db.Text)
    
    # Status
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending/reviewing/resolved/dismissed
    admin_notes = db.Column(db.Text)
    resolved_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime)
    
    # Relationships
    reporter = db.relationship("User", foreign_keys=[reporter_id], back_populates="reports_made")
    reported_user = db.relationship("User", foreign_keys=[reported_id], back_populates="reports_received")
    opportunity = db.relationship("Opportunity", back_populates="reports")
    resolver = db.relationship("User", foreign_keys=[resolved_by])
    
    def __repr__(self):
        return f"<Report {self.report_type} by User:{self.reporter_id} ({self.status})>"
    
    def resolve(self, admin_id, notes=None):
        """Resolve report"""
        self.status = 'resolved'
        self.resolved_at = datetime.utcnow()
        self.resolved_by = admin_id
        if notes:
            self.admin_notes = notes
        db.session.commit()
    
    def dismiss(self, admin_id, notes=None):
        """Dismiss report"""
        self.status = 'dismissed'
        self.resolved_at = datetime.utcnow()
        self.resolved_by = admin_id
        if notes:
            self.admin_notes = notes
        db.session.commit()


# ================= AUDIT LOG MODEL =================

class AuditLog(db.Model):
    """
    Admin activity audit trail
    Tracks all administrative actions for compliance and security
    """
    __tablename__ = "audit_logs"
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Who performed the action
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    admin_email = db.Column(db.String(120))  # Denormalized for faster queries
    
    # What action was performed
    action = db.Column(db.String(100), nullable=False)  # approve_opportunity, suspend_user, delete_application, etc.
    entity_type = db.Column(db.String(50), nullable=False)  # user, opportunity, application, report
    entity_id = db.Column(db.Integer)
    
    # Details
    description = db.Column(db.Text)
    old_value = db.Column(db.Text)  # JSON string of old state
    new_value = db.Column(db.Text)  # JSON string of new state
    
    # Context
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationship
    admin = db.relationship("User", foreign_keys=[admin_id])
    
    def __repr__(self):
        return f"<AuditLog {self.action} by Admin:{self.admin_id} at {self.created_at}>"
    
    @staticmethod
    def log_action(admin_id, action, entity_type, entity_id=None, description=None, 
                   old_value=None, new_value=None, ip_address=None):
        """
        Create audit log entry
        
        Args:
            admin_id: ID of admin performing action
            action: Action type (e.g., 'approve_opportunity')
            entity_type: Type of entity affected (e.g., 'opportunity')
            entity_id: ID of affected entity
            description: Human-readable description
            old_value: JSON string of old state
            new_value: JSON string of new state
            ip_address: IP address of admin
        """
        from flask import request
        
        admin = User.query.get(admin_id)
        
        log = AuditLog(
            admin_id=admin_id,
            admin_email=admin.email if admin else None,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            old_value=old_value,
            new_value=new_value,
            ip_address=ip_address or (request.remote_addr if request else None),
            user_agent=request.headers.get('User-Agent') if request else None
        )
        
        db.session.add(log)
        db.session.commit()
        
        return log


# ================= NOTIFICATION MODEL (Optional - Future Ready) =================

class Notification(db.Model):
    """
    User notifications system
    Future-ready for email/push notifications
    """
    __tablename__ = "notifications"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    
    # Notification content
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50))  # application_update, opportunity_approved, etc.
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime)
    
    # Link
    link = db.Column(db.String(200))
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationship
    user = db.relationship("User")
    
    def __repr__(self):
        return f"<Notification for User:{self.user_id} ({self.notification_type})>"
    
    def mark_as_read(self):
        """Mark notification as read"""
        self.is_read = True
        self.read_at = datetime.utcnow()
        db.session.commit()


# ================= DATABASE UTILITIES =================

def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully")


def create_admin_user(email, password, name="Admin"):
    """
    Create initial admin user
    
    Usage:
        from models import create_admin_user
        create_admin_user("admin@trustnex.com", "secure_password_123")
    """
    from werkzeug.security import generate_password_hash
    
    existing = User.query.filter_by(email=email).first()
    if existing:
        print(f"❌ Admin user {email} already exists")
        return existing
    
    admin = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        role='admin',
        is_active=True,
        is_verified=True
    )
    
    db.session.add(admin)
    db.session.commit()
    
    print(f"✅ Admin user created: {email}")
    return admin


# ================= QUERY HELPERS =================

class UserQueries:
    """Helper class for common user queries"""
    
    @staticmethod
    def get_active_users():
        """Get all active users"""
        return User.query.filter_by(is_active=True, deleted_at=None).all()
    
    @staticmethod
    def get_users_by_role(role):
        """Get users by role"""
        return User.query.filter_by(role=role, deleted_at=None).all()
    
    @staticmethod
    def get_suspended_users():
        """Get suspended users"""
        return User.query.filter_by(is_suspended=True).all()
    
    @staticmethod
    def get_recent_users(days=7):
        """Get users registered in last N days"""
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)
        return User.query.filter(User.created_at >= cutoff).all()


class OpportunityQueries:
    """Helper class for common opportunity queries"""
    
    @staticmethod
    def get_pending_opportunities():
        """Get opportunities awaiting approval"""
        return Opportunity.query.filter_by(status='pending', deleted_at=None).all()
    
    @staticmethod
    def get_approved_opportunities():
        """Get approved opportunities"""
        return Opportunity.query.filter_by(status='approved', is_active=True, deleted_at=None).all()
    
    @staticmethod
    def get_flagged_opportunities():
        """Get flagged opportunities"""
        return Opportunity.query.filter_by(status='flagged').all()


class ReportQueries:
    """Helper class for common report queries"""
    
    @staticmethod
    def get_pending_reports():
        """Get pending reports"""
        return Report.query.filter_by(status='pending').order_by(Report.created_at.desc()).all()
    
    @staticmethod
    def get_reports_by_type(report_type):
        """Get reports by type"""
        return Report.query.filter_by(report_type=report_type).all()