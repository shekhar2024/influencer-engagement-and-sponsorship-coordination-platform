from flask import render_template,request,redirect,url_for,flash, session
from app import app
from models import db,User,Campaign,Ad_Request,Flagged_User,Flagged_Campaign
from werkzeug.security import generate_password_hash,check_password_hash

@app.route('/')
def index():
    #authentication:if user_id is in session, then user is logged in
    if 'user_id' in session:
        return render_template('index.html')
    else:
        flash('Please login to access this page')
        return redirect(url_for('login'))
    

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
        flash('Please fill out all fields')
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
        flash('Please fill out all fields')
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