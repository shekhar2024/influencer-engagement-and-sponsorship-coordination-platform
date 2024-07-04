from app import app
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32),unique=True)
    passhash = db.Column(db.String(256),nullable=False)
    name = db.Column(db.String(64),nullable=True)
    industry = db.Column(db.String(100),nullable=True)
    budget = db.Column(db.Integer,nullable=True)
    category = db.Column(db.String(100),nullable=True)
    niche = db.Column(db.String(100),nullable=True)
    reach = db.Column(db.Integer,nullable=True)
    is_sponsor = db.Column(db.Boolean,nullable=False,default=False)
    is_influencer = db.Column(db.Boolean,nullable=False,default=False)
    is_admin = db.Column(db.Boolean,nullable=False,default=False)

    campaigns = db.relationship('Campaign',backref='sponsor',lazy=True)
    ad_requests = db.relationship('Ad_Request',backref='requester',lazy=True)
    flags = db.relationship('Flagged_User',backref='flagged_user',lazy=True)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100),nullable=False)
    description = db.Column(db.String(1000),nullable=True)
    start_date = db.Column(db.DateTime,nullable=False)
    end_date = db.Column(db.DateTime,nullable=False)
    budget = db.Column(db.Integer,nullable=False)
    category = db.Column(db.String(100),nullable=True)
    visibility = db.Column(db.Boolean,nullable=False,default=True)
    sponsor_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

    ad_requests = db.relationship('AdRequest',backref='campaign',lazy=True)
    flags = db.relationship('Flagged_Campaign',backref='flagged_campaign',lazy=True)

class Ad_Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    influencer_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    campaign_id = db.Column(db.Integer,db.ForeignKey('campaign.id'),nullable=False)
    status = db.Column(db.String(30),nullable=False,default='pending')
    message = db.Column(db.String(1000),nullable=True)
    payment = db.Column(db.Integer,nullable=True)
    requirements = db.Column(db.String(1000),nullable=True)

class Flagged_User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    
class Flagged_Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer,db.ForeignKey('campaign.id'),nullable=False)

with app.app_context():
    db.create_all()