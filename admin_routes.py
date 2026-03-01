"""
Admin Blueprint - Production-Ready Admin System
Complete administrative control system for TrustNex
"""

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import current_user
from models import (
    db, User, Opportunity, Application, Report, AuditLog, 
    Waitlist, Notification, UserQueries, OpportunityQueries, ReportQueries
)
from decorators import admin_required, audit_action, superadmin_required
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from sqlalchemy import func, desc
import json

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ================= DASHBOARD & ANALYTICS =================

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """
    Main admin dashboard with analytics overview
    """
    # User statistics
    total_users = User.query.filter_by(deleted_at=None).count()
    active_users = User.query.filter_by(is_active=True, deleted_at=None).count()
    students_count = User.query.filter_by(role='student', deleted_at=None).count()
    companies_count = User.query.filter_by(role='company', deleted_at=None).count()
    suspended_users = User.query.filter_by(is_suspended=True).count()
    
    # Opportunity statistics
    total_opportunities = Opportunity.query.filter_by(deleted_at=None).count()
    pending_opportunities = Opportunity.query.filter_by(status='pending', deleted_at=None).count()
    approved_opportunities = Opportunity.query.filter_by(status='approved', deleted_at=None).count()
    flagged_opportunities = Opportunity.query.filter_by(status='flagged').count()
    
    # Application statistics
    total_applications = Application.query.count()
    pending_applications = Application.query.filter_by(status='pending').count()
    approved_applications = Application.query.filter_by(status='approved').count()
    rejected_applications = Application.query.filter_by(status='rejected').count()
    spam_applications = Application.query.filter_by(is_spam=True).count()
    
    # Report statistics
    pending_reports = Report.query.filter_by(status='pending').count()
    total_reports = Report.query.count()
    
    # Growth statistics (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    new_users_this_week = User.query.filter(User.created_at >= week_ago).count()
    new_opportunities_this_week = Opportunity.query.filter(Opportunity.created_at >= week_ago).count()
    new_applications_this_week = Application.query.filter(Application.created_at >= week_ago).count()
    
    # Recent activity
    recent_users = User.query.filter_by(deleted_at=None).order_by(desc(User.created_at)).limit(5).all()
    recent_opportunities = Opportunity.query.filter_by(deleted_at=None).order_by(desc(Opportunity.created_at)).limit(5).all()
    recent_applications = Application.query.order_by(desc(Application.created_at)).limit(5).all()
    recent_reports = Report.query.order_by(desc(Report.created_at)).limit(5).all()
    
    # Waitlist
    waitlist_count = Waitlist.query.count()
    
    return render_template(
        'admin/dashboard.html',
        # User stats
        total_users=total_users,
        active_users=active_users,
        students_count=students_count,
        companies_count=companies_count,
        suspended_users=suspended_users,
        # Opportunity stats
        total_opportunities=total_opportunities,
        pending_opportunities=pending_opportunities,
        approved_opportunities=approved_opportunities,
        flagged_opportunities=flagged_opportunities,
        # Application stats
        total_applications=total_applications,
        pending_applications=pending_applications,
        approved_applications=approved_applications,
        rejected_applications=rejected_applications,
        spam_applications=spam_applications,
        # Report stats
        pending_reports=pending_reports,
        total_reports=total_reports,
        # Growth stats
        new_users_this_week=new_users_this_week,
        new_opportunities_this_week=new_opportunities_this_week,
        new_applications_this_week=new_applications_this_week,
        # Recent activity
        recent_users=recent_users,
        recent_opportunities=recent_opportunities,
        recent_applications=recent_applications,
        recent_reports=recent_reports,
        # Waitlist
        waitlist_count=waitlist_count
    )


# ================= USER MANAGEMENT =================

@admin_bp.route('/users')
@admin_required
def users():
    """View all users with filtering"""
    # Get filter parameters
    role_filter = request.args.get('role', 'all')
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '')
    
    # Build query
    query = User.query.filter_by(deleted_at=None)
    
    # Apply filters
    if role_filter != 'all':
        query = query.filter_by(role=role_filter)
    
    if status_filter == 'active':
        query = query.filter_by(is_active=True, is_suspended=False)
    elif status_filter == 'suspended':
        query = query.filter_by(is_suspended=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    
    # Apply search
    if search_query:
        query = query.filter(
            (User.name.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%'))
        )
    
    # Get results
    users = query.order_by(desc(User.created_at)).all()
    
    return render_template(
        'admin/users.html',
        users=users,
        role_filter=role_filter,
        status_filter=status_filter,
        search_query=search_query
    )


@admin_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    """View detailed user information"""
    user = User.query.get_or_404(user_id)
    
    # Get user's opportunities (if company)
    opportunities = []
    if user.role == 'company':
        opportunities = Opportunity.query.filter_by(user_id=user_id, deleted_at=None).all()
    
    # Get user's applications (if student)
    applications = []
    if user.role == 'student':
        applications = Application.query.filter_by(user_id=user_id).all()
    
    # Get reports made by user
    reports_made = Report.query.filter_by(reporter_id=user_id).all()
    
    # Get reports against user
    reports_received = Report.query.filter_by(reported_id=user_id).all()
    
    # Get audit logs for this user
    audit_logs = AuditLog.query.filter_by(entity_type='user', entity_id=user_id).order_by(desc(AuditLog.created_at)).limit(10).all()
    
    return render_template(
        'admin/user_detail.html',
        user=user,
        opportunities=opportunities,
        applications=applications,
        reports_made=reports_made,
        reports_received=reports_received,
        audit_logs=audit_logs
    )


@admin_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@admin_required
@audit_action('activate_user', 'user')
def activate_user(user_id):
    """Activate user account"""
    user = User.query.get_or_404(user_id)
    
    old_status = f"active={user.is_active}, suspended={user.is_suspended}"
    user.activate()
    new_status = f"active={user.is_active}, suspended={user.is_suspended}"
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='activate_user',
        entity_type='user',
        entity_id=user_id,
        description=f"Activated user {user.email}",
        old_value=old_status,
        new_value=new_status
    )
    
    flash(f"User {user.email} has been activated.", "success")
    return redirect(url_for('admin.user_detail', user_id=user_id))


@admin_bp.route('/users/<int:user_id>/suspend', methods=['POST'])
@admin_required
@audit_action('suspend_user', 'user')
def suspend_user(user_id):
    """Suspend user account"""
    user = User.query.get_or_404(user_id)
    
    # Prevent suspending other admins
    if user.role == 'admin' and user.id != current_user.id:
        flash("Cannot suspend other admin accounts.", "danger")
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    old_status = f"active={user.is_active}, suspended={user.is_suspended}"
    user.suspend()
    new_status = f"active={user.is_active}, suspended={user.is_suspended}"
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='suspend_user',
        entity_type='user',
        entity_id=user_id,
        description=f"Suspended user {user.email}",
        old_value=old_status,
        new_value=new_status
    )
    
    flash(f"User {user.email} has been suspended.", "success")
    return redirect(url_for('admin.user_detail', user_id=user_id))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
@audit_action('delete_user', 'user')
def delete_user(user_id):
    """Soft delete user account"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting admins
    if user.role == 'admin':
        flash("Cannot delete admin accounts.", "danger")
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    user.soft_delete()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='delete_user',
        entity_type='user',
        entity_id=user_id,
        description=f"Deleted user {user.email}"
    )
    
    flash(f"User {user.email} has been deleted.", "success")
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@admin_required
@audit_action('change_user_role', 'user')
def change_user_role(user_id):
    """Change user role"""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if new_role not in ['student', 'company', 'admin']:
        flash("Invalid role.", "danger")
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    # Prevent changing admin roles (security)
    if user.role == 'admin' or new_role == 'admin':
        flash("Admin role changes require superadmin access.", "danger")
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    old_role = user.role
    user.role = new_role
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='change_user_role',
        entity_type='user',
        entity_id=user_id,
        description=f"Changed {user.email} role from {old_role} to {new_role}",
        old_value=old_role,
        new_value=new_role
    )
    
    flash(f"User role changed to {new_role}.", "success")
    return redirect(url_for('admin.user_detail', user_id=user_id))


@admin_bp.route('/users/<int:user_id>/verify', methods=['POST'])
@admin_required
@audit_action('verify_user', 'user')
def verify_user(user_id):
    """Verify user/company account"""
    user = User.query.get_or_404(user_id)
    
    user.is_verified = True
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='verify_user',
        entity_type='user',
        entity_id=user_id,
        description=f"Verified user {user.email}"
    )
    
    flash(f"User {user.email} has been verified.", "success")
    return redirect(url_for('admin.user_detail', user_id=user_id))


# ================= COMPANY MANAGEMENT =================

@admin_bp.route('/companies')
@admin_required
def companies():
    """View all companies"""
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '')
    
    query = User.query.filter_by(role='company', deleted_at=None)
    
    if status_filter == 'verified':
        query = query.filter_by(is_verified=True)
    elif status_filter == 'unverified':
        query = query.filter_by(is_verified=False)
    elif status_filter == 'suspended':
        query = query.filter_by(is_suspended=True)
    
    if search_query:
        query = query.filter(
            (User.name.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%')) |
            (User.company_name.ilike(f'%{search_query}%'))
        )
    
    companies = query.order_by(desc(User.created_at)).all()
    
    return render_template(
        'admin/companies.html',
        companies=companies,
        status_filter=status_filter,
        search_query=search_query
    )


# ================= OPPORTUNITY MODERATION =================

@admin_bp.route('/opportunities')
@admin_required
def opportunities():
    """View all opportunities with moderation"""
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '')
    
    query = Opportunity.query.filter_by(deleted_at=None)
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if search_query:
        query = query.filter(Opportunity.title.ilike(f'%{search_query}%'))
    
    opportunities = query.order_by(desc(Opportunity.created_at)).all()
    
    return render_template(
        'admin/opportunities.html',
        opportunities=opportunities,
        status_filter=status_filter,
        search_query=search_query
    )


@admin_bp.route('/opportunities/<int:opp_id>')
@admin_required
def opportunity_detail(opp_id):
    """View detailed opportunity information"""
    opportunity = Opportunity.query.get_or_404(opp_id)
    
    # Get applications for this opportunity
    applications = Application.query.filter_by(opportunity_id=opp_id).all()
    
    # Get reports for this opportunity
    reports = Report.query.filter_by(opportunity_id=opp_id).all()
    
    # Get audit logs
    audit_logs = AuditLog.query.filter_by(entity_type='opportunity', entity_id=opp_id).order_by(desc(AuditLog.created_at)).limit(10).all()
    
    return render_template(
        'admin/opportunity_detail.html',
        opportunity=opportunity,
        applications=applications,
        reports=reports,
        audit_logs=audit_logs
    )


@admin_bp.route('/opportunities/<int:opp_id>/approve', methods=['POST'])
@admin_required
@audit_action('approve_opportunity', 'opportunity')
def approve_opportunity(opp_id):
    """Approve opportunity"""
    opportunity = Opportunity.query.get_or_404(opp_id)
    
    old_status = opportunity.status
    opportunity.approve(current_user.id)
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='approve_opportunity',
        entity_type='opportunity',
        entity_id=opp_id,
        description=f"Approved opportunity: {opportunity.title}",
        old_value=old_status,
        new_value='approved'
    )
    
    flash(f"Opportunity '{opportunity.title}' has been approved.", "success")
    return redirect(url_for('admin.opportunity_detail', opp_id=opp_id))


@admin_bp.route('/opportunities/<int:opp_id>/reject', methods=['POST'])
@admin_required
@audit_action('reject_opportunity', 'opportunity')
def reject_opportunity(opp_id):
    """Reject opportunity"""
    opportunity = Opportunity.query.get_or_404(opp_id)
    
    old_status = opportunity.status
    opportunity.reject()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='reject_opportunity',
        entity_type='opportunity',
        entity_id=opp_id,
        description=f"Rejected opportunity: {opportunity.title}",
        old_value=old_status,
        new_value='rejected'
    )
    
    flash(f"Opportunity '{opportunity.title}' has been rejected.", "success")
    return redirect(url_for('admin.opportunity_detail', opp_id=opp_id))


@admin_bp.route('/opportunities/<int:opp_id>/flag', methods=['POST'])
@admin_required
@audit_action('flag_opportunity', 'opportunity')
def flag_opportunity(opp_id):
    """Flag opportunity for review"""
    opportunity = Opportunity.query.get_or_404(opp_id)
    
    old_status = opportunity.status
    opportunity.flag()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='flag_opportunity',
        entity_type='opportunity',
        entity_id=opp_id,
        description=f"Flagged opportunity: {opportunity.title}",
        old_value=old_status,
        new_value='flagged'
    )
    
    flash(f"Opportunity '{opportunity.title}' has been flagged.", "warning")
    return redirect(url_for('admin.opportunity_detail', opp_id=opp_id))


@admin_bp.route('/opportunities/<int:opp_id>/feature', methods=['POST'])
@admin_required
@audit_action('feature_opportunity', 'opportunity')
def feature_opportunity(opp_id):
    """Mark opportunity as featured"""
    opportunity = Opportunity.query.get_or_404(opp_id)
    
    opportunity.is_featured = not opportunity.is_featured
    opportunity.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='feature_opportunity',
        entity_type='opportunity',
        entity_id=opp_id,
        description=f"{'Featured' if opportunity.is_featured else 'Unfeatured'} opportunity: {opportunity.title}"
    )
    
    status = "featured" if opportunity.is_featured else "unfeatured"
    flash(f"Opportunity '{opportunity.title}' has been {status}.", "success")
    return redirect(url_for('admin.opportunity_detail', opp_id=opp_id))


@admin_bp.route('/opportunities/<int:opp_id>/delete', methods=['POST'])
@admin_required
@audit_action('delete_opportunity', 'opportunity')
def delete_opportunity(opp_id):
    """Soft delete opportunity"""
    opportunity = Opportunity.query.get_or_404(opp_id)
    
    opportunity.soft_delete()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='delete_opportunity',
        entity_type='opportunity',
        entity_id=opp_id,
        description=f"Deleted opportunity: {opportunity.title}"
    )
    
    flash(f"Opportunity '{opportunity.title}' has been deleted.", "success")
    return redirect(url_for('admin.opportunities'))


# ================= APPLICATION MONITORING =================

@admin_bp.route('/applications')
@admin_required
def applications():
    """View all applications"""
    status_filter = request.args.get('status', 'all')
    
    query = Application.query
    
    if status_filter != 'all':
        if status_filter == 'spam':
            query = query.filter_by(is_spam=True)
        else:
            query = query.filter_by(status=status_filter)
    
    applications = query.order_by(desc(Application.created_at)).all()
    
    return render_template(
        'admin/applications.html',
        applications=applications,
        status_filter=status_filter
    )


@admin_bp.route('/applications/<int:app_id>/spam', methods=['POST'])
@admin_required
@audit_action('mark_spam', 'application')
def mark_spam(app_id):
    """Mark application as spam"""
    application = Application.query.get_or_404(app_id)
    
    application.mark_as_spam()
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='mark_spam',
        entity_type='application',
        entity_id=app_id,
        description=f"Marked application {app_id} as spam"
    )
    
    flash("Application marked as spam.", "success")
    return redirect(request.referrer or url_for('admin.applications'))


# ================= REPORT MANAGEMENT =================

@admin_bp.route('/reports')
@admin_required
def reports():
    """View all reports"""
    status_filter = request.args.get('status', 'all')
    type_filter = request.args.get('type', 'all')
    
    query = Report.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if type_filter != 'all':
        query = query.filter_by(report_type=type_filter)
    
    reports = query.order_by(desc(Report.created_at)).all()
    
    return render_template(
        'admin/reports.html',
        reports=reports,
        status_filter=status_filter,
        type_filter=type_filter
    )


@admin_bp.route('/reports/<int:report_id>')
@admin_required
def report_detail(report_id):
    """View detailed report information"""
    report = Report.query.get_or_404(report_id)
    
    return render_template(
        'admin/report_detail.html',
        report=report
    )


@admin_bp.route('/reports/<int:report_id>/resolve', methods=['POST'])
@admin_required
@audit_action('resolve_report', 'report')
def resolve_report(report_id):
    """Resolve report"""
    report = Report.query.get_or_404(report_id)
    admin_notes = request.form.get('notes', '')
    
    report.resolve(current_user.id, admin_notes)
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='resolve_report',
        entity_type='report',
        entity_id=report_id,
        description=f"Resolved report {report_id}"
    )
    
    flash("Report has been resolved.", "success")
    return redirect(url_for('admin.report_detail', report_id=report_id))


@admin_bp.route('/reports/<int:report_id>/dismiss', methods=['POST'])
@admin_required
@audit_action('dismiss_report', 'report')
def dismiss_report(report_id):
    """Dismiss report"""
    report = Report.query.get_or_404(report_id)
    admin_notes = request.form.get('notes', '')
    
    report.dismiss(current_user.id, admin_notes)
    
    # Log action
    AuditLog.log_action(
        admin_id=current_user.id,
        action='dismiss_report',
        entity_type='report',
        entity_id=report_id,
        description=f"Dismissed report {report_id}"
    )
    
    flash("Report has been dismissed.", "info")
    return redirect(url_for('admin.report_detail', report_id=report_id))


# ================= AUDIT LOGS =================

@admin_bp.route('/logs')
@admin_required
def audit_logs():
    """View audit logs"""
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filters
    action_filter = request.args.get('action', 'all')
    entity_filter = request.args.get('entity', 'all')
    admin_filter = request.args.get('admin', 'all')
    
    query = AuditLog.query
    
    if action_filter != 'all':
        query = query.filter_by(action=action_filter)
    
    if entity_filter != 'all':
        query = query.filter_by(entity_type=entity_filter)
    
    if admin_filter != 'all':
        query = query.filter_by(admin_id=int(admin_filter))
    
    logs = query.order_by(desc(AuditLog.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get unique admins for filter
    admins = db.session.query(User).filter_by(role='admin').all()
    
    return render_template(
        'admin/audit_logs.html',
        logs=logs,
        admins=admins,
        action_filter=action_filter,
        entity_filter=entity_filter,
        admin_filter=admin_filter
    )


# ================= WAITLIST MANAGEMENT =================

@admin_bp.route('/waitlist')
@admin_required
def waitlist():
    """View waitlist entries"""
    entries = Waitlist.query.order_by(desc(Waitlist.created_at)).all()
    
    return render_template('admin/waitlist.html', entries=entries)


# ================= SETTINGS (FUTURE READY) =================

@admin_bp.route('/settings')
@superadmin_required
def settings():
    """System settings (future implementation)"""
    return render_template('admin/settings.html')


# ================= API ENDPOINTS (For AJAX) =================

@admin_bp.route('/api/stats')
@admin_required
def api_stats():
    """Return dashboard stats as JSON"""
    stats = {
        'users': {
            'total': User.query.filter_by(deleted_at=None).count(),
            'active': User.query.filter_by(is_active=True, deleted_at=None).count(),
            'students': User.query.filter_by(role='student', deleted_at=None).count(),
            'companies': User.query.filter_by(role='company', deleted_at=None).count(),
        },
        'opportunities': {
            'total': Opportunity.query.filter_by(deleted_at=None).count(),
            'pending': Opportunity.query.filter_by(status='pending', deleted_at=None).count(),
            'approved': Opportunity.query.filter_by(status='approved', deleted_at=None).count(),
        },
        'applications': {
            'total': Application.query.count(),
            'pending': Application.query.filter_by(status='pending').count(),
        }
    }
    
    return jsonify(stats)


@admin_bp.route('/api/search-users')
@admin_required
def api_search_users():
    """Search users API endpoint"""
    query = request.args.get('q', '')
    
    users = User.query.filter(
        (User.name.ilike(f'%{query}%')) |
        (User.email.ilike(f'%{query}%'))
    ).filter_by(deleted_at=None).limit(10).all()
    
    results = [{
        'id': u.id,
        'name': u.name,
        'email': u.email,
        'role': u.role
    } for u in users]
    
    return jsonify(results)


# ================= ERROR HANDLERS =================

@admin_bp.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors in admin section"""
    return render_template('admin/404.html'), 404


@admin_bp.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors in admin section"""
    return render_template('admin/403.html'), 403


@admin_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors in admin section"""
    db.session.rollback()
    return render_template('admin/500.html'), 500