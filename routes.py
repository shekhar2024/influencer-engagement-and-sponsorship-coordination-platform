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

    if user.flag:
        flash("Your account has been flagged, you can't login")
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
    flash('Registered successfully')
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
    flash('Registered successfully')
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
    elif user.is_admin:
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('influencer'))

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
    sponsor = User.query.get(session['user_id'])
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    new_requests = 0
    negotiations = 0
    completed = 0
    for campaign in campaigns:
        if not campaign.flag:
            if campaign.status == 'pending':
                for request in campaign.ad_requests_byinfluencer:
                    if not request.influencer.flag:
                        if request.status == 'pending':
                            new_requests += 1

        if not campaign.flag:
            if campaign.status == 'pending':
                for request in campaign.ad_requests_bysponsor:
                    if not request.influencer.flag:
                        if request.status == 'In Negotiation':
                            negotiations += 1

        if campaign.status == 'Completed' or campaign.status == 'Paid':
            completed += 1

    return render_template('sponsor.html', sponsor=sponsor, campaigns=campaigns, new_requests=new_requests, negotiations=negotiations, completed=completed)

@app.route('/campaign/payment/<int:id>')
@sponsor_required
def payment(id):
    campaign = Campaign.query.get(id)
    sponsor = campaign.sponsor
    for request in campaign.ad_requests_byinfluencer:
        if request.status == 'Accepted' or request.status == 'Negotiated':
            pay = request.payment
            influencer = request.influencer
            break

    for request in campaign.ad_requests_bysponsor:
        if request.status == 'Accepted' or request.status == 'Negotiated':
            pay = request.payment
            influencer = request.influencer
            break

    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('completed_requests_sponsor'))

    if not campaign.status == 'Completed':
        flash('This campaign is not completed yet or already paid')
        return redirect(url_for('completed_requests_sponsor'))

    return render_template('campaign/payment.html', campaign=campaign, pay = pay, influencer=influencer, sponsor=sponsor)

@app.route('/campaign/payment/<int:id>', methods=['POST'])
@sponsor_required
def payment_post(id):
    campaign = Campaign.query.get(id)

    for request in campaign.ad_requests_byinfluencer:
        if request.status == 'Accepted' or request.status == 'Negotiated':
            pay = request.payment
            influencer = request.influencer
            break

    for request in campaign.ad_requests_bysponsor:
        if request.status == 'Accepted' or request.status == 'Negotiated':
            pay = request.payment
            influencer = request.influencer
            break

    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('completed_requests_sponsor'))

    if not campaign.status == 'Completed':
        flash('This campaign is not completed yet or already paid')
        return redirect(url_for('completed_requests_sponsor'))

    campaign.status = 'Paid'
    db.session.commit()

    flash("Payment of ₹"+str(pay)+ ' made successfully to '+influencer.username)
    return redirect(url_for('completed_requests_sponsor'))


@app.route('/campaign')
@sponsor_required
def campaigns():
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    return render_template('campaigns.html', campaigns=campaigns)

@app.route('/campaign/add')
@sponsor_required
def add_campaign():
    now = datetime.now().strftime('%Y-%m-%d')
    return render_template('campaign/add_campaign.html', now=now)

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


    if start_date > end_date:
        flash('End date cannot be before start date')
        return redirect(url_for('add_campaign'))

    new_campaign = Campaign(title=title, description=description, start_date=start_date, end_date=end_date, budget=budget, category=category, visibility=visibility, sponsor_id=session['user_id'])
    db.session.add(new_campaign)
    db.session.commit()
    flash('Campaign added successfully')
    return redirect(url_for('campaigns'))

@app.route('/campaign/<int:id>')
@authenticate
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
    now = datetime.now().strftime('%Y-%m-%d')
    return render_template('campaign/edit_campaign.html', campaign=campaign, now=now)

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
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    requests = Ad_Request_byinfluencer.query.filter_by(campaign_id=id).all()
    return render_template('campaign/recieved_requests.html', campaign=campaign, requests=requests)

@app.route('/campaign/accept_request/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def accept_request_sponsor(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('campaigns'))
    if request.status == 'pending':
        request.status = 'Accepted'
        request.campaign.status = 'Active'
        db.session.commit()
    return redirect(url_for('campaigns'))

@app.route('/campaign/accept_new_request/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def accept_new_request_sponsor(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('new_requests_sponsor'))
    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('new_requests_sponsor'))
    if request.status == 'pending':
        request.status = 'Accepted'
        request.campaign.status = 'Active'
        db.session.commit()

    requests_1 = Ad_Request_bysponsor.query.all()
    for req in requests_1:
        if req.status == 'pending' or req.status == 'In Negotiation':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    requests_2 = Ad_Request_byinfluencer.query.all()
    for req in requests_2:
        if req.status == 'pending':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()
    return redirect(url_for('new_requests_sponsor'))

@app.route('/campaign/accept_negotiated_request/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def accept_negotiated_request_sponsor(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('campaigns'))
    if not request.status == 'In Negotiation':
        flash('This request is not in negotiation')
        return redirect(url_for('campaigns'))

    request.status = 'Negotiated'
    request.campaign.status = 'Active'
    db.session.commit()

    requests_1 = Ad_Request_bysponsor.query.all()
    for req in requests_1:
        if req.status == 'pending' or req.status == 'In Negotiation':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    requests_2 = Ad_Request_byinfluencer.query.all()
    for req in requests_2:
        if req.status == 'pending':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    return redirect(url_for('campaigns'))

@app.route('/campaign/accept_negotiated_request_dashboard/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def accept_negotiated_request_dashboard(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('negotiations_sponsor'))
    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('negotiations_sponsor'))
    if not request.status == 'In Negotiation':
        flash('This request is not in negotiation')
        return redirect(url_for('negotiations_sponsor'))

    request.status = 'Negotiated'
    request.campaign.status = 'Active'
    db.session.commit()

    requests_1 = Ad_Request_bysponsor.query.all()
    for req in requests_1:
        if req.status == 'pending' or req.status == 'In Negotiation':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    requests_2 = Ad_Request_byinfluencer.query.all()
    for req in requests_2:
        if req.status == 'pending':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    return redirect(url_for('negotiations_sponsor'))

@app.route('/campaign/reject_negotiated_request/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def reject_negotiated_request_sponsor(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('campaigns'))
    if not request.status == 'In Negotiation':
        flash('This request is not in negotiation')
        return redirect(url_for('campaigns'))

    request.status = 'Negotiation Rejected'
    db.session.commit()
    return redirect(url_for('campaigns'))

@app.route('/campaign/reject_negotiated_request_dashboard/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def reject_negotiated_request_dashboard(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('negotiations_sponsor'))
    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('negotiations_sponsor'))
    if not request.status == 'In Negotiation':
        flash('This request is not in negotiation')
        return redirect(url_for('negotiations_sponsor'))

    request.status = 'Negotiation Rejected'
    db.session.commit()
    return redirect(url_for('negotiations_sponsor'))

@app.route('/campaign/reject_request/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def reject_request_sponsor(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    if request.status == 'pending':
        request.status = 'Rejected'
        db.session.commit()
    return redirect(url_for('recieved_requests_sponsor', id=request.campaign_id))

@app.route('/campaign/reject_new_request/<int:request_id>', methods=['GET','POST'])
@sponsor_required
def reject_new_request_sponsor(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('new_requests_sponsor'))
    if request.status == 'pending':
        request.status = 'Rejected'
        db.session.commit()
    return redirect(url_for('new_requests_sponsor', id=request.campaign_id))

@app.route('/campaign/<int:campaign_id>/request/add')
@sponsor_required
def add_request_sponsor(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id'], status='pending').all()
    influencers = User.query.filter_by(is_influencer=True).all()
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/add_request.html', campaign=campaign, influencers=influencers, campaigns=campaigns)


@app.route('/campaign/<int:campaign_id>/request/add', methods=['POST'])
@sponsor_required
def add_request_sponsor_post(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))
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

@app.route('/campaign/request_bysponsor/<int:request_id>/view')
@sponsor_required
def view_request_sponsor_bysponsor(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    
    return render_template('campaign/view_request.html', request=request)

@app.route('/campaign/request_byinfluencer/<int:request_id>/view')
@sponsor_required
def view_request_sponsor_byinfluencer(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))

    return render_template('campaign/view_request.html', request=request)

@app.route('/campaign/request/<int:request_id>/edit')
@sponsor_required
def edit_request_sponsor(request_id):
    influencers = User.query.filter_by(is_influencer=True).all()
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/edit_request.html', request=request, influencers=influencers, campaigns=campaigns)

@app.route('/campaign/request/<int:request_id>/edit', methods=['POST'])
@sponsor_required
def edit_request_sponsor_post(request_id):
    req = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    campaign_id = request.form.get('campaign_id')
    influencer_id = request.form.get('influencer_id')
    payment = request.form.get('payment')
    requirements = request.form.get('requirements')

    campaign = Campaign.query.get(campaign_id)
    influencer = User.query.get(influencer_id)

    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('campaigns'))

    if not influencer:
        flash('Influencer does not exist')
        return redirect(url_for('edit_request_sponsor', request_id=request_id))

    campaign_name = campaign.title
    influencer_username = influencer.username

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('edit_request_sponsor', request_id=request_id))

    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('edit_request_sponsor', request_id=request_id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('edit_request_sponsor', request_id=request_id))

    req.influencer_name = influencer_username
    req.influencer_id = influencer_id
    req.campaign_title = campaign_name
    req.campaign_id = campaign_id
    req.payment = payment
    req.requirements = requirements
    db.session.commit()

    flash('Request updated successfully')
    return redirect(url_for('sent_requests_sponsor', id=campaign_id))

@app.route('/campaign/request/<int:request_id>/delete')
@sponsor_required
def delete_request_sponsor(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    return render_template('campaign/delete_request.html', request=request)

@app.route('/campaign/request/<int:request_id>/delete', methods=['POST'])
@sponsor_required
def delete_request_sponsor_post(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('campaigns'))
    campaign_id = request.campaign_id
    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully')
    return redirect(url_for('sent_requests_sponsor', id=campaign_id))

@app.route('/find_influencers')
@sponsor_required
def find_influencers():
    influencers = User.query.filter_by(is_influencer=True).all()
    parameter = request.args.get('parameter')
    query = request.args.get('query')
    if parameter == 'username':
        influencers = User.query.filter(User.username.ilike(f'%{query}%')).all()
        return render_template('find_influencers.html', influencers=influencers)
    if parameter == 'name':
        influencers = User.query.filter(User.name.ilike(f'%{query}%')).all()
        return render_template('find_influencers.html', influencers=influencers)
    if parameter == 'category':
        influencers = User.query.filter(User.category.ilike(f'%{query}%')).all()
        return render_template('find_influencers.html', influencers=influencers)
    if parameter == 'min_reach':
        try:
            query = int(query)
        except ValueError:
            flash('Invalid entry')
            return render_template('find_influencers.html', influencers=influencers)

        if query < 0:
            flash('minimum reach cannot be negative')
            return render_template('find_influencers.html', influencers=influencers)
        
        influencers = User.query.filter(User.reach >= query).all()
        return render_template('find_influencers.html', influencers=influencers)
    if parameter == 'niche':
        influencers = User.query.filter(User.niche.ilike(f'%{query}%')).all()
        return render_template('find_influencers.html', influencers=influencers)
    return render_template('find_influencers.html', influencers=influencers)

@app.route('/find_influenecrs/<int:id>/request')
@sponsor_required
def request_influencer(id):
    influencers = User.query.filter_by(is_influencer=True).all()
    influencer = User.query.get(id)
    if not influencer:
        flash('Influencer does not exist')
        return redirect(url_for('find_influencers'))
    campaigns = Campaign.query.filter_by(sponsor_id=session['user_id'], status='pending').all()
    return render_template('campaign/request_influencer.html', influencer=influencer, campaigns=campaigns, influencers=influencers)

@app.route('/find_influenecrs/<int:id>/request', methods=['POST'])
@sponsor_required
def request_influencer_post(id):
    influencer = User.query.get(id)
    if not influencer:
        flash('Influencer does not exist')
        return redirect(url_for('find_influencers'))
    camp_id = request.form.get('campaign_id')
    payment = request.form.get('payment')
    requirements = request.form.get('requirements')
    influencer_id = request.form.get('influencer_id')

    campaign = Campaign.query.get(camp_id)
    influencer = User.query.get(influencer_id)

    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('find_influencers'))
    
    if not influencer:
        flash('Influencer does not exist')
        return redirect(url_for('find_influencers'))

    campaign_name = campaign.title
    influencer_username = influencer.username

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('request_influencer', id=influencer_id))

    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('request_influencer', id=influencer_id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('request_influencer', id=influencer_id))

    new_request = Ad_Request_bysponsor(influencer_name=influencer_username, influencer_id=influencer_id, campaign_title=campaign_name, campaign_id=camp_id, payment=payment, requirements=requirements)
    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully')
    return redirect(url_for('find_influencers'))

@app.route('/campaign/new_requests')
@sponsor_required
def new_requests_sponsor():
    sponsor = User.query.get(session['user_id'])
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    return render_template('campaign/new_requests.html', sponsor=sponsor, campaigns=campaigns)

@app.route('/campaign/negotiations')
@sponsor_required
def negotiations_sponsor():
    sponsor = User.query.get(session['user_id'])
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    return render_template('campaign/negotiations.html', sponsor=sponsor, campaigns=campaigns)

@app.route('/campaign/completed')
@sponsor_required
def completed_requests_sponsor():
    sponsor = User.query.get(session['user_id'])
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    return render_template('campaign/completed.html', sponsor=sponsor, campaigns=campaigns)


#-----Admin Pages-----#

@app.route('/find_users')
@admin_required
def find_users():
    users = User.query.all()
    parameter = request.args.get('parameter')
    query = request.args.get('query')
    if parameter == 'username':
        users = User.query.filter(User.username.ilike(f'%{query}%')).all()
        return render_template('admin/find_users.html', users=users)
    if parameter == 'name':
        users = User.query.filter(User.name.ilike(f'%{query}%')).all()
        return render_template('admin/find_users.html', users=users)
    if parameter == 'industry':
        users = User.query.filter(User.industry.ilike(f'%{query}%')).all()
        return render_template('admin/find_users.html', users=users)
    if parameter == 'min_reach':
        try:
            query = int(query)
        except ValueError:
            flash('Invalid entry')
            return render_template('admin/find_users.html', users=users)

        if query < 0:
            flash('minimum reach cannot be negative')
            return render_template('admin/find_users.html', users=users)
        
        users = User.query.filter(User.reach >= query).all()
        return render_template('admin/find_users.html', users=users)
    if parameter == 'category':
        users = User.query.filter(User.category.ilike(f'%{query}%')).all()
        return render_template('admin/find_users.html', users=users)
    if parameter == 'niche':
        users = User.query.filter(User.niche.ilike(f'%{query}%')).all()
        return render_template('admin/find_users.html', users=users)
    if parameter == 'roll':
        users = User.query.filter(User.is_sponsor==True).all()
        return render_template('admin/find_users.html', users=users)
    return render_template('admin/find_users.html', users=users)

@app.route('/flag_user/<int:id>')
@admin_required
def flag_user(id):
    user = User.query.get(id)
    if not user:
        flash('User does not exist')
        return redirect(url_for('find_users'))
    return render_template('admin/flag_user.html', user=user)
    
@app.route('/flag_user/<int:id>', methods=['POST'])
@admin_required
def flag_user_post(id):
    user = User.query.get(id)
    if not user:
        flash('User does not exist')
        return redirect(url_for('find_users'))
    new_flag = Flagged_User(user_id=id)
    db.session.add(new_flag)
    db.session.commit()
    flash('User flagged successfully')
    return redirect(url_for('find_users'))

@app.route('/unflag_user/<int:id>', methods=['GET','POST'])
@admin_required
def unflag_user(id):
    user = User.query.get(id)
    if not user:
        flash('User does not exist')
        return redirect(url_for('find_users'))
    flag = Flagged_User.query.filter_by(user_id=id).first()
    db.session.delete(flag)
    db.session.commit()
    flash('User unflagged successfully')
    return redirect(url_for('find_users'))

@app.route('/find_campaigns')
@admin_required
def find_campaigns():
    campaigns = Campaign.query.all()
    parameter = request.args.get('parameter')
    query = request.args.get('query')
    if parameter == 'title':
        campaigns = Campaign.query.filter(Campaign.title.ilike(f'%{query}%')).all()
        return render_template('admin/find_campaigns.html', campaigns=campaigns)
    if parameter == 'category':
        campaigns = Campaign.query.filter(Campaign.category.ilike(f'%{query}%')).all()
        return render_template('admin/find_campaigns.html', campaigns=campaigns)
    if parameter == 'min_budget':
        try:
            query = int(query)

        except ValueError:
            flash('Invalid entry')
            return render_template('admin/find_campaigns.html', campaigns=campaigns)

        if query < 0:
            flash('minimum budget cannot be negative')
            return render_template('admin/find_campaigns.html', campaigns=campaigns)

        campaigns = Campaign.query.filter(Campaign.budget >= query).all()
        return render_template('admin/find_campaigns.html', campaigns=campaigns)

    return render_template('admin/find_campaigns.html', campaigns=campaigns) 

@app.route('/flag_campaign/<int:id>')
@admin_required
def flag_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('find_campaigns'))
    return render_template('admin/flag_campaign.html', campaign=campaign)

@app.route('/flag_campaign/<int:id>', methods=['POST'])
@admin_required
def flag_campaign_post(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('find_campaigns'))
    new_flag = Flagged_Campaign(campaign_id=id)
    db.session.add(new_flag)
    db.session.commit()
    flash('Campaign flagged successfully')
    return redirect(url_for('find_campaigns'))

@app.route('/unflag_campaign/<int:id>', methods=['GET','POST'])
@admin_required
def unflag_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('find_campaigns'))
    flag = Flagged_Campaign.query.filter_by(campaign_id=id).first()
    db.session.delete(flag)
    db.session.commit()
    flash('Campaign unflagged successfully')
    return redirect(url_for('find_campaigns'))

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    flagged_users = Flagged_User.query.all()
    flagged_campaigns = Flagged_Campaign.query.all()
    sponsors = User.query.filter_by(is_sponsor=True).all()
    influencers = User.query.filter_by(is_influencer=True).all()
    public_campaigns = Campaign.query.filter_by(visibility='Public').count()
    private_campaigns = Campaign.query.filter_by(visibility='Private').count()
    request_sponsor = Ad_Request_bysponsor.query.all()
    request_influencer = Ad_Request_byinfluencer.query.all()
    request_accepted_sponsor = Ad_Request_byinfluencer.query.filter_by(status='Accepted').count()
    request_accepted_influencer = Ad_Request_bysponsor.query.filter_by(status='Accepted').count()
    return render_template('admin/admin_dashboard.html', flagged_users=flagged_users, flagged_campaigns=flagged_campaigns, sponsors=sponsors, influencers=influencers, public_campaigns=public_campaigns, private_campaigns=private_campaigns, request_sponsor=request_sponsor, request_influencer=request_influencer, request_accepted_sponsor=request_accepted_sponsor, request_accepted_influencer=request_accepted_influencer)

@app.route('/admin_dashboard/unflag_user/<int:id>')
@admin_required
def unflag_user_dashboard(id):
    flag = Flagged_User.query.get(id)
    if not flag:
        flash('User is not flagged or does not exist')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(flag)
    db.session.commit()
    flash('User unflagged successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_dashboard/unflag_campaign/<int:id>')
@admin_required
def unflag_campaign_dashboard(id):
    flag = Flagged_Campaign.query.get(id)
    if not flag:
        flash('Campaign is not flagged or does not exist')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(flag)
    db.session.commit()
    flash('Campaign unflagged successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:id>')
@admin_required
def delete_user(id):
    user = User.query.get(id)
    if not user:
        flash('User does not exist')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/delete_user.html', user=user)

@app.route('/admin/delete_user/<int:id>', methods=['POST'])
@admin_required
def delete_user_post(id):
    user = User.query.get(id)
    if not user:
        flash('User does not exist')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_campaign/<int:id>')
@admin_required
def delete_campaign_admin(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/delete_campaign.html', campaign=campaign)

@app.route('/admin/delete_campaign/<int:id>', methods=['POST'])
@admin_required
def delete_campaign_post_admin(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/stats')
@admin_required
def admin_stats():
    campaigns = Campaign.query.all()

    campaign_categories = []
    category_data = []
    for campaign in campaigns:
        if campaign.category not in campaign_categories:
            campaign_categories.append(campaign.category)
            category_data.append(1)
        else:
            x=0
            for i in campaign_categories:
                if campaign.category == i:
                    break
                x+=1
            category_data[x] += 1

    pending_campaigns = 0
    active = 0
    completed = 0   
    unpaid = 0
    paid = 0

    for campaign in campaigns:
        if campaign.status == 'pending':
            pending_campaigns += 1
        if campaign.status == 'Active':
            active += 1
        if campaign.status == 'Completed' or campaign.status == 'Paid':
            completed += 1

            if campaign.status == 'Completed':
                unpaid += 1
            if campaign.status == 'Paid':
                paid += 1

    reqeusts_1 = Ad_Request_bysponsor.query.all()
    requests_2 = Ad_Request_byinfluencer.query.all()
    requests = reqeusts_1 + requests_2
    pending_requests = 0
    accepted = 0
    rejected = 0
    for request in requests:
        if request.status == 'pending':
            pending_requests += 1
        if request.status == 'Accepted' or request.status == 'Negotiated':
            accepted += 1
        if request.status == 'Rejected' or request.status == 'Negotiation Rejected':
            rejected += 1

    

        
    return render_template('admin/stats.html', campaign_categories=campaign_categories, category_data=category_data, pending_campaigns=pending_campaigns, active=active, completed=completed, pending_requests=pending_requests, accepted=accepted, rejected=rejected, unpaid=unpaid, paid=paid)

#-----Influencer Pages-----#

@app.route('/influencer/find_campaigns')
@influencer_required
def find_campaigns_influencer():
    campaigns = Campaign.query.all()
    parameter = request.args.get('parameter')
    query = request.args.get('query')
    if parameter == 'title':
        campaigns = Campaign.query.filter(Campaign.title.ilike(f'%{query}%')).all()
        return render_template('influencer/find_campaigns.html', campaigns=campaigns)
    if parameter == 'category':
        campaigns = Campaign.query.filter(Campaign.category.ilike(f'%{query}%')).all()
        return render_template('influencer/find_campaigns.html', campaigns=campaigns)
    if parameter == 'min_budget':
        try:
            query = int(query)

        except ValueError:
            flash('Invalid entry')
            return render_template('influencer/find_campaigns.html', campaigns=campaigns)

        if query < 0:
            flash('minimum budget cannot be negative')
            return render_template('influencer/find_campaigns.html', campaigns=campaigns)

        campaigns = Campaign.query.filter(Campaign.budget >= query).all()
        return render_template('influencer/find_campaigns.html', campaigns=campaigns)
        
    return render_template('influencer/find_campaigns.html', campaigns=campaigns)

@app.route('/request_campaign/<int:id>')
@influencer_required
def request_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('find_campaigns_influencer'))
    if not campaign.visibility == 'Public':
        flash('Campaign is private')
        return redirect(url_for('find_campaigns_influencer'))
    return render_template('influencer/request_campaign.html', campaign=campaign)

@app.route('/request_campaign/<int:id>', methods=['POST'])
@influencer_required
def request_campaign_post(id):
    influencer = User.query.get(session['user_id'])
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('find_campaigns_influencer'))
    if not campaign.visibility == 'Public':
        flash('Campaign is private')
        return redirect(url_for('find_campaigns_influencer'))
    if not campaign.status == 'pending':
        flash('You can only request for pending campaigns')
        return redirect(url_for('find_campaigns_influencer'))
    payment = request.form.get('payment')
    requirements = request.form.get('requirements')

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('request_campaign', id=id))

    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('request_campaign', id=id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('request_campaign', id=id))

    influencer_name = influencer.username
    influencer_id = influencer.id
    campaign_name = campaign.title

    new_request = Ad_Request_byinfluencer(influencer_name=influencer_name, influencer_id=influencer_id, campaign_title=campaign_name, campaign_id=id, payment=payment, requirements=requirements)
    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully')
    return redirect(url_for('find_campaigns_influencer'))

@app.route('/influencer/recieved_requests')
@influencer_required
def recieved_requests_influencer():
    influencer = User.query.get(session['user_id'])
    requests = influencer.ad_requests_bysponsor
    y = 0
    for request in requests:
        if not request.campaign.sponsor.flag:
            if not request.campaign.flag:
                if request.status == 'pending' and request.campaign.status == 'pending':
                    y+=1
                
    return render_template('influencer/recieved_requests.html', requests=requests, y=y)

@app.route('/influencer/accept_request/<int:request_id>', methods=['GET','POST'])
@influencer_required
def accept_request_influencer(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('recieved_requests_influencer'))

    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('recieved_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('recieved_requests_influencer'))
        
    request.status = 'Accepted'
    request.campaign.status = 'Active'
    db.session.commit()

    requests_1 = Ad_Request_bysponsor.query.all()
    for req in requests_1:
        if req.status == 'pending' or req.status == 'In Negotiation':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    requests_2 = Ad_Request_byinfluencer.query.all()
    for req in requests_2:
        if req.status == 'pending':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    return redirect(url_for('recieved_requests_influencer'))

@app.route('/influencer/accept_new_request/<int:request_id>', methods=['GET','POST'])
@influencer_required
def accept_new_request_influencer(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('new_requests_influencer'))

    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('new_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('new_requests_influencer'))
        
    request.status = 'Accepted'
    request.campaign.status = 'Active'
    db.session.commit()

    requests_1 = Ad_Request_bysponsor.query.all()
    for req in requests_1:
        if req.status == 'pending' or req.status == 'In Negotiation':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    requests_2 = Ad_Request_byinfluencer.query.all()
    for req in requests_2:
        if req.status == 'pending':
            if not req.campaign.status == 'pending':
                req.status = 'Rejected'
                db.session.commit()

    return redirect(url_for('new_requests_influencer'))

@app.route('/influencer/reject_request/<int:request_id>', methods=['GET','POST'])
@influencer_required
def reject_request_influencer(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('recieved_requests_influencer'))

    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('recieved_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('recieved_requests_influencer'))

    request.status = 'Rejected'
    db.session.commit()
    return redirect(url_for('recieved_requests_influencer'))

@app.route('/influencer/reject_new_request/<int:request_id>', methods=['GET','POST'])
@influencer_required
def reject_new_request_influencer(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('new_requests_influencer'))

    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('new_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('new_requests_influencer'))

    request.status = 'Rejected'
    db.session.commit()
    return redirect(url_for('new_requests_influencer'))

@app.route('/influencer/negotiate_request/<int:request_id>')
@influencer_required
def negotiate_request_influencer(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    campaign = request.campaign
    if not request:
        flash('Request does not exist')
        return redirect(url_for('recieved_requests_influencer'))

    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('recieved_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is not pending')
        return redirect(url_for('recieved_requests_influencer'))

    return render_template('influencer/negotiate_request.html', request=request, campaign=campaign)

@app.route('/influencer/negotiate_request/<int:request_id>', methods=['POST'])
@influencer_required
def negotiate_request_influencer_post(request_id):
    user = User.query.get(session['user_id'])
    req = Ad_Request_bysponsor.query.get(request_id)
    if not req:
        flash('Request does not exist')
        return redirect(url_for('recieved_requests_influencer'))
    if not req.status == 'pending':
        flash('Request is not pending')
        return redirect(url_for('recieved_requests_influencer'))
    if not req.campaign.status == 'pending':
        flash('Campaign is either active or completed')
        return redirect(url_for('recieved_requests_influencer'))
    
    payment = request.form.get('payment')
    requirements = request.form.get('requirements')

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('negotiate_request_influencer', request_id=request_id))
    
    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('negotiate_request_influencer', request_id=request_id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('negotiate_request_influencer', request_id=request_id))

    req.payment = payment
    req.requirements = requirements
    req.status = 'In Negotiation'
    db.session.commit()
    
    return redirect(url_for('recieved_requests_influencer'))

@app.route('/influencer/negotiate_new_requests/<int:request_id>')
@influencer_required
def negotiate_new_request_influencer(request_id):
    request = Ad_Request_bysponsor.query.get(request_id)
    campaign = request.campaign
    if not request:
        flash('Request does not exist')
        return redirect(url_for('new_requests_influencer'))

    if not request.campaign.status == 'pending':
        flash('This campaign is either active or completed')
        return redirect(url_for('new_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is not pending')
        return redirect(url_for('new_requests_influencer'))

    return render_template('influencer/negotiate_request.html', request=request, campaign=campaign)

@app.route('/influencer/negotiate_new_requests/<int:request_id>', methods=['POST'])
@influencer_required
def negotiate_new_request_influencer_post(request_id):
    user = User.query.get(session['user_id'])
    req = Ad_Request_bysponsor.query.get(request_id)
    if not req:
        flash('Request does not exist')
        return redirect(url_for('new_requests_influencer'))
    if not req.status == 'pending':
        flash('Request is not pending')
        return redirect(url_for('new_requests_influencer'))
    if not req.campaign.status == 'pending':
        flash('Campaign is either active or completed')
        return redirect(url_for('new_requests_influencer'))
    
    payment = request.form.get('payment')
    requirements = request.form.get('requirements')

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('negotiate_new_request_influencer', request_id=request_id))
    
    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('negotiate_new_request_influencer', request_id=request_id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('negotiate_new_request_influencer', request_id=request_id))

    req.payment = payment
    req.requirements = requirements
    req.status = 'In Negotiation'
    db.session.commit()
    
    return redirect(url_for('new_requests_influencer'))

@app.route('/influencer/negotiated_requests')
@influencer_required
def negotiated_requests_influencer():
    influencer = User.query.get(session['user_id'])
    requests = influencer.ad_requests_bysponsor
    return render_template('influencer/negotiated_requests.html', requests=requests)

@app.route('/influencer/sent_requests')
@influencer_required
def sent_requests_influencer():
    influencer = User.query.get(session['user_id'])
    requests = influencer.ad_requests_byinfluencer
    return render_template('influencer/sent_requests.html', requests=requests)

@app.route('/influencer/<int:request_id>/edit')
@influencer_required
def edit_request_influencer(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('sent_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('sent_requests_influencer'))
        
    return render_template('influencer/edit_request.html', request=request)

@app.route('/influencer/<int:request_id>/edit', methods=['POST'])
@influencer_required
def edit_request_influencer_post(request_id):
    req = Ad_Request_byinfluencer.query.get(request_id)
    if not req:
        flash('Request does not exist')
        return redirect(url_for('sent_requests_influencer'))

    if not req.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('sent_requests_influencer'))

    payment = request.form.get('payment')
    requirements = request.form.get('requirements')

    if not payment or not requirements:
        flash('Please fill out all the required fields')
        return redirect(url_for('edit_request_influencer', request_id=request_id))
    
    try:
        payment = float(payment)
    except ValueError:
        flash('Invalid payment amount')
        return redirect(url_for('edit_request_influencer', request_id=request_id))

    if payment < 0:
        flash('Payment cannot be negative')
        return redirect(url_for('edit_request_influencer', request_id=request_id))

    req.payment = payment
    req.requirements = requirements
    db.session.commit()
    return redirect(url_for('sent_requests_influencer'))

@app.route('/influencer/<int:request_id>/delete')
@influencer_required
def delete_request_influencer(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('sent_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('sent_requests_influencer'))

    return render_template('influencer/delete_request.html', request=request)

@app.route('/influencer/<int:request_id>/delete', methods=['POST'])
@influencer_required
def delete_request_influencer_post(request_id):
    request = Ad_Request_byinfluencer.query.get(request_id)
    if not request:
        flash('Request does not exist')
        return redirect(url_for('sent_requests_influencer'))

    if not request.status == 'pending':
        flash('Request is already accepted or rejected')
        return redirect(url_for('sent_requests_influencer'))

    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully')
    return redirect(url_for('sent_requests_influencer'))

@app.route('/influencer')
@influencer_required
def influencer():
    influencer = User.query.get(session['user_id'])
    requests_1 = influencer.ad_requests_bysponsor
    requests_2 = influencer.ad_requests_byinfluencer
    requests = requests_1 + requests_2
    x = 0
    y = 0
    for request in requests_1:
        if request.campaign.status == 'Active' or request.campaign.status == 'Completed':
            x+=1

    for request in requests_2:
        if request.campaign.status == 'Active' or request.campaign.status == 'Completed':
            x+=1

    for request in requests_1:
        if not request.campaign.sponsor.flag:
            if request.status == 'pending' and request.campaign.status == 'pending':
                y+=1

    a = 0
    for request in requests:
        if request.status =='Accepted' or request.status == 'Negotiated':
            if request.campaign.status == 'Completed' or request.campaign.status == 'Paid':
                a+=1

    return render_template('influencer/influencer.html', influencer=influencer, requests_1=requests_1, requests_2=requests_2, x=x, y=y, a=a)
    
@app.route('/influencer/mark_completed/<int:id>', methods=['GET', 'POST'])
@influencer_required
def mark_completed(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign does not exist')
        return redirect(url_for('influencer'))
    if not campaign.status == 'Active':
        flash('Campaign is not active')
        return redirect(url_for('influencer'))
    campaign.status = 'Completed'
    db.session.commit()
    return redirect(url_for('influencer'))

@app.route('/influencer/new_requests')
@influencer_required
def new_requests_influencer():
    influencer = User.query.get(session['user_id'])
    requests = influencer.ad_requests_bysponsor
    y = 0
    for request in requests:
        if not request.campaign.sponsor.flag:
            if not request.campaign.flag:
                if request.status == 'pending' and request.campaign.status == 'pending':
                    y+=1
    return render_template('influencer/new_requests.html', requests=requests, y=y)

@app.route('/influencer/completed_requests')
@influencer_required
def completed_requests_influencer():
    influencer = User.query.get(session['user_id'])
    requests_1 = influencer.ad_requests_bysponsor
    requests_2 = influencer.ad_requests_byinfluencer
    requests = requests_1 + requests_2

    return render_template('influencer/completed.html', requests=requests)
