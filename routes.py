from flask import render_template,request,redirect,url_for,flash, session
from app import app
from models import db,User,Campaign,Ad_Request_bysponsor,Ad_Request_byinfluencer,Flagged_User,Flagged_Campaign
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from datetime import datetime


@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/sponsor_register')
def sponsor_register():
    return render_template('sponsor_register.html')

@app.route('/influencer_register')
def influencer_register():
    return render_template('influencer_register.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Please fill out all fields')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash('User does not exist')
        return redirect(url_for('login'))

    if not check_password_hash(user.passhash, password):
        flash('Incorrect password')
        return redirect(url_for('login'))

    #send the session cookie
    session['user_id'] = user.id
    session['is_sponsor'] = user.is_sponsor
    session['is_influencer'] = user.is_influencer
    session['is_admin'] = user.is_admin
    flash('Logged in successfully')
    return redirect(url_for('index'))

@app.route('/sponsor_register', methods=['POST'])
def sponsor_register_post():
    username = request.form.get('username')   
    name = request.form.get('name')
    industry = request.form.get('industry')
    budget = request.form.get('budget')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not username or not password or not confirm_password:
        flash('Please fill out all the required fields')
        return redirect(url_for('sponsor_register'))

    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('sponsor_register'))

    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists')
        return redirect(url_for('sponsor_register'))

    password_hash = generate_password_hash(password)

    new_user = User(username=username, name=name, industry=industry, budget=budget, passhash=password_hash, is_sponsor=True)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/influencer_register', methods=['POST'])
def influencer_register_post():
    username = request.form.get('username')
    name = request.form.get('name')
    category = request.form.get('category')
    niche = request.form.get('niche')
    reach = request.form.get('reach')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if not username or not password or not confirm_password:
        flash('Please fill out all the required fields')
        return redirect(url_for('influencer_register'))

    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('influencer_register'))
    
    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists')
        return redirect(url_for('influencer_register'))

    password_hash = generate_password_hash(password)

    new_user = User(username=username, name=name, category=category, niche=niche, reach=reach, passhash=password_hash, is_influencer=True)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

#-----

#decorator for authenticate

def authenticate(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to access this page')
            return redirect(url_for('login'))
    return inner

def sponsor_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.is_sponsor:
            return func(*args, **kwargs)
        else:
            flash('You are not authorized to go to this page')
            return redirect(url_for('index'))
    return inner

def influencer_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.is_influencer:
            return func(*args, **kwargs)
        else:
            flash('You are not authorized to go to this page')
            return redirect(url_for('index'))
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.is_admin:
            return func(*args, **kwargs)
        else:
            flash('You are not authorized to go to this page')
            return redirect(url_for('index'))
    return inner

@app.route('/')
@authenticate
def index():
    user = User.query.get(session['user_id'])
    if user.is_sponsor:
        return redirect(url_for('sponsor'))
    return render_template('index.html')

@app.route('/sponsor_profile')
@sponsor_required
def sponsor_profile():
    user = User.query.get(session['user_id'])
    return render_template('sponsor_profile.html', user=user)

    
@app.route('/influencer_profile')
@influencer_required
def influencer_profile():
    user = User.query.get(session['user_id'])
    return render_template('influencer_profile.html', user=user)


@app.route('/admin_profile')
@admin_required
def admin_profile():
    user = User.query.get(session['user_id'])
    return render_template('admin_profile.html', user=user)


@app.route('/sponsor_profile', methods=['POST'])
@authenticate
def sponsor_profile_post():
    username = request.form.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    name = request.form.get('name')
    industry = request.form.get('industry')
    budget = request.form.get('budget')

    if not username or not current_password or not new_password:
        flash('Please fill out all the required fields')
        return redirect(url_for('sponsor_profile'))

    user = User.query.get(session['user_id'])
    if not check_password_hash(user.passhash, current_password):
        flash('Incorrect password')
        return redirect(url_for('sponsor_profile'))

    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists')
            return redirect(url_for('sponsor_profile'))
    
    new_password_hash = generate_password_hash(new_password)
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    user.industry = industry
    user.budget = budget
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('sponsor_profile'))

@app.route('/influencer_profile', methods=['POST'])
@authenticate
def influencer_profile_post():
    username = request.form.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    name = request.form.get('name')
    category = request.form.get('category')
    niche = request.form.get('niche')
    reach = request.form.get('reach')

    if not username or not current_password or not new_password:
        flash('Please fill out all the required fields')
        return redirect(url_for('influencer_profile'))

    user = User.query.get(session['user_id'])
    if not check_password_hash(user.passhash, current_password):
        flash('Incorrect password')
        return redirect(url_for('influencer_profile'))

    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists')
            return redirect(url_for('influencer_profile'))
    
    new_password_hash = generate_password_hash(new_password)
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    user.category = category
    user.niche = niche
    user.reach = reach
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('influencer_profile'))

@app.route('/admin_profile', methods=['POST'])
@authenticate
def admin_profile_post():
    username = request.form.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    name = request.form.get('name')
    
    if not username or not current_password or not new_password:
        flash('Please fill out all the required fields')
        return redirect(url_for('admin_profile'))

    user = User.query.get(session['user_id'])
    if not check_password_hash(user.passhash, current_password):
        flash('Incorrect password')
        return redirect(url_for('admin_profile'))

    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists')
            return redirect(url_for('admin_profile'))
    
    new_password_hash = generate_password_hash(new_password)
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('admin_profile'))

@app.route('/logout')
@authenticate
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

#-----Sponsor Pages-----#

@app.route('/sponsor')
@sponsor_required
def sponsor():
    return render_template('sponsor.html')

@app.route('/campaign')
@sponsor_required
def campaigns():
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    return render_template('campaigns.html', campaigns=campaigns)

@app.route('/campaign/add')
@sponsor_required
def add_campaign():
    return render_template('campaign/add_campaign.html')

@app.route('/campaign/add', methods=['POST'])
@sponsor_required
def add_campaign_post():
    title = request.form.get('title')
    description = request.form.get('description')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    budget = request.form.get('budget')
    category = request.form.get('category')
    visibility = request.form.get('visibility')

    if not title or not start_date or not end_date or not budget or not visibility:
        flash('Please fill out all the required fields')
        return redirect(url_for('add_campaign'))

    start_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_date = datetime.strptime(end_date, '%Y-%m-%d')

    try:
        budget = float(budget)
    except ValueError:
        flash('Invalid budget amount')
        return redirect(url_for('add_campaign'))

    if budget < 0:
        flash('Budget cannot be negative')
        return redirect(url_for('add_campaign'))

    if start_date < datetime.now():
        flash('Start date cannot be before today')

    if start_date > end_date:
        flash('End date cannot be before start date')

    new_campaign = Campaign(title=title, description=description, start_date=start_date, end_date=end_date, budget=budget, category=category, visibility=visibility, sponsor_id=session['user_id'])
    db.session.add(new_campaign)
    db.session.commit()
    flash('Campaign added successfully')
    return redirect(url_for('campaigns'))

@app.route('/campaign/<int:id>')
@sponsor_required
def view_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/view_campaign.html', campaign=campaign)

@app.route('/campaign/<int:id>/edit')
@sponsor_required
def edit_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/edit_campaign.html', campaign=campaign)

@app.route('/campaign/<int:id>/edit', methods=['POST'])
@sponsor_required
def edit_campaign_post(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    title = request.form.get('title')
    description = request.form.get('description')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    budget = request.form.get('budget')
    category = request.form.get('category')
    visibility = request.form.get('visibility')
    if not title or not start_date or not end_date or not budget or not visibility:
        flash('Please fill out all the required fields')
        return redirect(url_for('edit_campaign', id=id))
    start_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_date = datetime.strptime(end_date, '%Y-%m-%d')
    try:
        budget = float(budget)
    except ValueError:
        flash('Invalid budget amount')
        return redirect(url_for('edit_campaign', id=id))
    if budget < 0:
        flash('Budget cannot be negative')
        return redirect(url_for('edit_campaign', id=id))
    if start_date < datetime.now():
        flash('Start date cannot be before today')
        return redirect(url_for('edit_campaign', id=id))
    if start_date > end_date:
        flash('End date cannot be before start date')
        return redirect(url_for('edit_campaign', id=id))

    campaign.title = title
    campaign.description = description
    campaign.start_date = start_date
    campaign.end_date = end_date
    campaign.budget = budget
    campaign.category = category
    campaign.visibility = visibility
    db.session.commit()
    flash('Campaign updated successfully')
    return redirect(url_for('campaigns'))

@app.route('/campaign/<int:id>/delete')
@sponsor_required
def delete_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/delete_campaign.html', campaign=campaign)

@app.route('/campaign/<int:id>/delete', methods=['POST'])
@sponsor_required
def delete_campaign_post(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted successfully')
    return redirect(url_for('campaigns'))

@app.route('/campaign/<int:id>/sent_requests')
@sponsor_required
def sent_requests_sponsor(id):
    campaign = Campaign.query.get(id)
    requests = Ad_Request_bysponsor.query.filter_by(campaign_id=id).all()
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/sent_requests.html', campaign=campaign, requests=requests)

@app.route('/campaign/<int:id>/recieved_requests')
@sponsor_required
def recieved_requests_sponsor(id):
    campaign = Campaign.query.get(id)
    requests = Ad_Request_byinfluencer.query.filter_by(campaign_id=id).all()
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/recieved_requests.html', campaign=campaign, requests=requests)

@app.route('/campaign/<int:campaign_id>/request/add')
@sponsor_required
def add_request_sponsor(campaign_id):
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    influencers = User.query.filter_by(is_influencer=True).all()
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/add_request.html', campaign=campaign, influencers=influencers, campaigns=campaigns)


@app.route('/campaign/<int:campaign_id>/request/add', methods=['POST'])
@sponsor_required
def add_request_sponsor_post(campaign_id):
    camp_id = request.form.get('campaign_id')
    influencer_id = request.form.get('influencer_id')
    payment = request.form.get('payment')
    requirements = request.form.get('requirements')

    campaign = Campaign.query.get(camp_id)
    influencer = User.query.get(influencer_id)

    campaign_name = campaign.title
    influencer_username = influencer.username

    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))

    if not influencer:
        flash('Influencer does not exist')
        return redirect(url_for('add_request_sponsor'))

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('add_request_sponsor', campaign_id=camp_id))

    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('add_request_sponsor', campaign_id=camp_id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('add_request_sponsor', campaign_id=camp_id))

    new_request = Ad_Request_bysponsor(influencer_name=influencer_username, influencer_id=influencer_id, campaign_title=campaign_name, campaign_id=camp_id, payment=payment, requirements=requirements)
    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully')
    return redirect(url_for('sent_requests_sponsor', id=camp_id))

@app.route('/campaign/request/<int:request_id>/view')
@sponsor_required
def view_request_sponsor(request_id):
    request_1 = Ad_Request_bysponsor.query.get(request_id)
    request_2 = Ad_Request_byinfluencer.query.get(request_id)
    if not request_1 and not request_2:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    if request_1:
        request = request_1
    else:
        request = request_2
    return render_template('campaign/view_request.html', request=request)


    

    
