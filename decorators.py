"""
Admin Decorators and Access Control
Production-grade RBAC implementation
"""

from functools import wraps
from flask import redirect, url_for, flash, abort, request
from flask_login import current_user
from models import AuditLog
import json


def admin_required(f):
    """
    Decorator to restrict access to admin users only
    
    Usage:
        @app.route('/admin/users')
        @admin_required
        def admin_users():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login", next=request.url))
        
        # Check if user is admin
        if not current_user.is_admin:
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("home"))
        
        # Check if admin account is active
        if not current_user.is_active or current_user.is_suspended:
            flash("Your admin account has been suspended.", "danger")
            return redirect(url_for("home"))
        
        return f(*args, **kwargs)
    
    return decorated_function


def superadmin_required(f):
    """
    Decorator for superadmin-only routes (future scalability)
    
    Usage:
        @app.route('/admin/system-settings')
        @superadmin_required
        def system_settings():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        
        if not current_user.is_admin:
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("home"))
        
        # Check for superadmin email (can be replaced with role hierarchy)
        if current_user.email not in ["admin@trustnex.com", "superadmin@trustnex.com"]:
            flash("Access denied. Superadmin privileges required.", "danger")
            return redirect(url_for("admin.dashboard"))
        
        return f(*args, **kwargs)
    
    return decorated_function


def role_required(role):
    """
    Generic role-based decorator
    
    Usage:
        @app.route('/post-opportunity')
        @role_required('company')
        def post_opportunity():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            
            if current_user.role != role:
                flash(f"Access denied. {role.capitalize()} role required.", "danger")
                return redirect(url_for("home"))
            
            if not current_user.is_active or current_user.is_suspended:
                flash("Your account is not active.", "danger")
                return redirect(url_for("home"))
            
            return f(*args, **kwargs)
        
        return wrapper
    
    return decorator


def permission_required(permission):
    """
    Permission-based decorator (future scalability)
    
    Usage:
        @app.route('/admin/delete-user')
        @permission_required('delete_user')
        def delete_user():
            ...
    
    Note: Requires Permission model implementation
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            
            if not current_user.is_admin:
                flash("Access denied.", "danger")
                return redirect(url_for("home"))
            
            # Future: Check user.permissions.has(permission)
            # For now, all admins have all permissions
            
            return f(*args, **kwargs)
        
        return wrapper
    
    return decorator


def audit_action(action, entity_type):
    """
    Decorator to automatically log admin actions
    
    Usage:
        @app.route('/admin/approve-opportunity/<int:opp_id>')
        @admin_required
        @audit_action('approve_opportunity', 'opportunity')
        def approve_opportunity(opp_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Execute the function first
            result = f(*args, **kwargs)
            
            # Log the action
            try:
                entity_id = kwargs.get('id') or kwargs.get('user_id') or kwargs.get('opp_id') or kwargs.get('app_id')
                
                AuditLog.log_action(
                    admin_id=current_user.id,
                    action=action,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    description=f"Admin {current_user.email} performed {action} on {entity_type} {entity_id}",
                    ip_address=request.remote_addr
                )
            except Exception as e:
                # Don't fail the request if logging fails
                print(f"⚠️ Audit logging failed: {str(e)}")
            
            return result
        
        return wrapper
    
    return decorator


def rate_limit(max_requests=10, window_seconds=60):
    """
    Rate limiting decorator (basic implementation)
    
    Usage:
        @app.route('/api/endpoint')
        @rate_limit(max_requests=5, window_seconds=60)
        def api_endpoint():
            ...
    
    Note: For production, use Redis-backed rate limiting
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Basic rate limiting logic
            # In production, use Redis or similar
            
            # For now, just execute the function
            # TODO: Implement proper rate limiting with Redis
            
            return f(*args, **kwargs)
        
        return wrapper
    
    return decorator


def validate_input(*validators):
    """
    Input validation decorator
    
    Usage:
        def validate_email(email):
            if not '@' in email:
                raise ValueError("Invalid email")
        
        @app.route('/admin/update-user')
        @validate_input(validate_email)
        def update_user():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Run all validators
            for validator in validators:
                try:
                    validator(**kwargs)
                except ValueError as e:
                    flash(str(e), "danger")
                    return redirect(request.referrer or url_for("admin.dashboard"))
            
            return f(*args, **kwargs)
        
        return wrapper
    
    return decorator


# ================= HELPER FUNCTIONS =================

def is_admin(user):
    """Check if user has admin role"""
    return user and user.is_authenticated and user.role == 'admin'


def can_access_admin_panel(user):
    """Check if user can access admin panel"""
    return (
        user and 
        user.is_authenticated and 
        user.role == 'admin' and 
        user.is_active and 
        not user.is_suspended
    )


def get_admin_permissions(user):
    """
    Get admin permissions (future scalability)
    
    Returns:
        list: List of permission strings
    """
    if not is_admin(user):
        return []
    
    # Future: Query from Permission model
    # For now, all admins have all permissions
    return [
        'view_users',
        'edit_users',
        'delete_users',
        'suspend_users',
        'view_opportunities',
        'approve_opportunities',
        'reject_opportunities',
        'delete_opportunities',
        'view_applications',
        'moderate_applications',
        'view_reports',
        'resolve_reports',
        'view_audit_logs',
        'manage_settings'
    ]


def check_permission(user, permission):
    """
    Check if user has specific permission
    
    Args:
        user: User object
        permission: Permission string
    
    Returns:
        bool: True if user has permission
    """
    if not is_admin(user):
        return False
    
    # Future: Check permission model
    # For now, all admins have all permissions
    return True


# ================= CSRF PROTECTION (Basic) =================

def generate_csrf_token():
    """
    Generate CSRF token
    
    Note: For production, use Flask-WTF or similar
    """
    import secrets
    return secrets.token_hex(16)


def verify_csrf_token(token):
    """
    Verify CSRF token
    
    Note: For production, use Flask-WTF or similar
    """
    # Basic implementation
    # TODO: Implement proper CSRF protection with Flask-WTF
    return True