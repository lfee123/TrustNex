from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


# ================= USER MODEL =================

class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)

    role = db.Column(db.String(20), nullable=False)  # student / company


    def __repr__(self):
        return f"<User {self.email}>"
    

# ================= WAITLIST =================

class Waitlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(50))  # student / company
    org_name = db.Column(db.String(150))


# # ================= OPPORTUNITIES =================

# class Opportunity(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(200))
#     company = db.Column(db.String(150))
#     trust_score = db.Column(db.Integer)
#     type = db.Column(db.String(50))  # internship / job / challenge
#     description = db.Column(db.Text)

# ================= OPPORTUNITY MODEL =================

class Opportunity(db.Model):

    __tablename__ = "opportunities"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    title = db.Column(db.String(200), nullable=False)

    opportunity_type = db.Column(db.String(50))  # internship/job/challenge

    description = db.Column(db.Text)

    skills = db.Column(db.String(300))

    task = db.Column(db.Text)

    duration = db.Column(db.String(100))

    paid = db.Column(db.String(20))  # paid/unpaid

    contact = db.Column(db.String(150))

    user = db.relationship("User", backref="opportunities")


class Application(db.Model):

    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    opportunity_id = db.Column(db.Integer, db.ForeignKey("opportunities.id"))

    status = db.Column(db.String(20), default="Pending")  # Pending / Approved / Rejected

    message = db.Column(db.Text)

    user = db.relationship("User", backref="applications")

    opportunity = db.relationship("Opportunity", backref="applications")