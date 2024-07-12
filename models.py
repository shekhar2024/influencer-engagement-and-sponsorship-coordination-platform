from app import app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

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
    ad_requests_bysponsor = db.relationship('Ad_Request_bysponsor',backref='sponsor',lazy=True)
    ad_requests_byinfluencer = db.relationship('Ad_Request_byinfluencer',backref='influencer',lazy=True)
    flag = db.relationship('Flagged_User',backref='flagged_user',uselist=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100),nullable=False)
    description = db.Column(db.String(1000),nullable=True)
    start_date = db.Column(db.DateTime,nullable=False)
    end_date = db.Column(db.DateTime,nullable=False)
    budget = db.Column(db.Integer,nullable=False)
    category = db.Column(db.String(100),nullable=True)
    visibility = db.Column(db.String(32),nullable=False,default='Public')
    status = db.Column(db.String(30),nullable=False,default='pending')
    sponsor_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

    ad_requests_bysponsor = db.relationship('Ad_Request_bysponsor',backref='campaign',lazy=True, cascade='all, delete-orphan')
    ad_requests_byinfluencer = db.relationship('Ad_Request_byinfluencer',backref='campaign',lazy=True, cascade='all, delete-orphan')
    flag = db.relationship('Flagged_Campaign',backref='flagged_campaign',uselist=False, cascade='all, delete-orphan')

class Ad_Request_bysponsor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    influencer_name = db.Column(db.String(64),nullable=True)
    influencer_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    campaign_title = db.Column(db.String(100),nullable=True)
    campaign_id = db.Column(db.Integer,db.ForeignKey('campaign.id'),nullable=False)
    status = db.Column(db.String(30),nullable=False,default='pending')
    payment = db.Column(db.Integer,nullable=True)
    requirements = db.Column(db.String(1000),nullable=True)

class Ad_Request_byinfluencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    influencer_name = db.Column(db.String(64),nullable=True)
    influencer_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    campaign_title = db.Column(db.String(100),nullable=True)
    campaign_id = db.Column(db.Integer,db.ForeignKey('campaign.id'),nullable=False)
    status = db.Column(db.String(30),nullable=False,default='pending')
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
#if admin exists, else create admin
    if not User.query.filter_by(is_admin=True).first():
        password_hash = generate_password_hash('admin')
        admin = User(username='admin', name="Admin", passhash=password_hash,is_admin=True)
        db.session.add(admin)
        db.session.commit()

    


