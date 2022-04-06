from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import func, column
from werkzeug.security import generate_password_hash, check_password_hash
import json
import website
from . import db
from .models import User
from sqlalchemy.sql import text
import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
# This file SHOULD contain all Web routes/views that would require users to be signed in
auth = Blueprint('auth', __name__)
model = pickle.load(open("rfr.pkl", "rb"))
standard_to = StandardScaler()

def verification():
    if request.method == 'POST':
        if request.form.get('type') == 'login':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember=True)
                    flash(f'Welcome back {current_user.username}', category='success')
                    redirect(url_for('auth.predict'))
                else:
                    flash('login failed', category='error')
            else:
                flash('login failed', category='error')
        if request.form.get('type') == 'register':
            email = request.form.get('email')
            username = request.form.get('username')
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')

            user = User.query.filter_by(email=email).first()
            user_name = User.query.filter_by(username=username).first()

            if user:
                flash('email already exists', category='error')
            if user_name:
                flash('username is taken', category='error')
            if len(email) < 7:
                flash('The email must be greater than 7 characters', category='error')
            if len(username) < 3:
                flash('name must me greater than 3 characters', category='error')
            if len(password1) < 8:
                flash('password must be greater than 8 characters', category='error')
            elif password1 != password2:
                flash('passwords do not match', category='error')
            else:
                new_user = User(email=email,
                                username=username,
                                password=generate_password_hash(password1, method='sha256'))

                db.session.add(new_user)
                db.session.commit()
                user = User.query.filter_by(email=email).first()
                login_user(user, remember=True)
                flash(f'Hello {current_user.username}!', category='success')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    # return redirect('/') also works but if changed in future would need to come back and code it again
    return redirect(url_for('auth.login'))

@auth.route('/create-account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        user_name = User.query.filter_by(username=username).first()
        if user:
            flash('email already exists', category='error')
        elif user_name:
            flash('username is taken', category='error')
        elif len(email) < 7:
            flash('The email must be greater than 7 characters', category='error')
        elif len(username) < 3:
            flash('name must me greater than 3 characters', category='error')
        elif len(password1) < 8:
            flash('password must be greater than 8 characters', category='error')
        elif password1 != password2:
            flash('passwords do not match', category='error')
        else:
            new_user = User(email=email,
                            username=username,
                            password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(email=email).first()
            login_user(user, remember=True)
            flash('Account added', category='success')
            #  return redirect('/') also works but if changed in future would need to come back and code it again
            return redirect(url_for('auth.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    Fuel_Type_Diesel = 0

    if request.method == 'POST':
        yearOfRegistration = int(request.form['yearOfRegistration'])
        kilometer = int(request.form['kilometer'])
        vehicleType = int(request.form['vehicleType'])
        fuelType = request.form['fuelType']
        gearbox = request.form['gearbox']
        powerPS = request.form['powerPS']
        monthOfRegistration = request.form['monthOfRegistration']
        notRepairedDamage = request.form['notRepairedDamage']

        prediction = model.predict(np.array([[vehicleType,
                                              yearOfRegistration,
                                              gearbox,
                                              powerPS,
                                              kilometer,
                                              monthOfRegistration,
                                              fuelType,
                                              notRepairedDamage]]))
        output = round(prediction[0], 2)
        if output < 0:
            return render_template('predict.html', prediction_texts="Sorry you cannot sell this car", user=current_user)
        else:
            print(output * 1.3)
            prediction_text="You can sell the Car at ${} ".format(output * 1.3)
            flash(f'{prediction_text}', category='success')
            return render_template('predict.html', prediction_text="You can sell the Car at ${} ".format(output * 1.3), user=current_user)
    else:
        return render_template("predict.html", user=current_user)

@auth.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('type') == 'login':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember=True)
                    flash(f'Welcome back {current_user.username}', category='success')
                    return render_template('predict.html', user=current_user)
                else:
                    flash('login failed', category='error')
            else:
                flash('login failed', category='error')
        if request.form.get('type') == 'register':
            email = request.form.get('email')
            username = request.form.get('username')
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')

            user = User.query.filter_by(email=email).first()
            user_name = User.query.filter_by(username=username).first()

            if user:
                flash('email already exists', category='error')
            if user_name:
                flash('username is taken', category='error')
            if len(email) < 7:
                flash('The email must be greater than 7 characters', category='error')
            if len(username) < 3:
                flash('name must me greater than 3 characters', category='error')
            if len(password1) < 8:
                flash('password must be greater than 8 characters', category='error')
            elif password1 != password2:
                flash('passwords do not match', category='error')
            else:
                new_user = User(email=email,
                                username=username,
                                password=generate_password_hash(password1, method='sha256'))

                db.session.add(new_user)
                db.session.commit()
                user = User.query.filter_by(email=email).first()
                login_user(user, remember=True)
                flash(f'Hello {current_user.username}!', category='success')
                return render_template('predict.html', user=current_user)
        
    return render_template("login.html", user=current_user)