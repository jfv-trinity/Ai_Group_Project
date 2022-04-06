from flask import Blueprint, render_template, jsonify, request, flash, session, url_for
from flask_login import login_required, current_user
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import redirect
from website import db
from website.auth import verification
from website.models import User
import json

import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler

views = Blueprint('views', __name__)
model = pickle.load(open("rfr.pkl", "rb"))
standard_to = StandardScaler()


@views.route('register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        verification()
        return render_template('home.html', user=current_user)
    return render_template("register.html", user=current_user)


@views.route("/predict", methods=['POST'])
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
            return render_template('index.html', prediction_texts="Sorry you cannot sell this car")
        else:
            print(output * 1.3)
            return render_template('index.html', prediction_text="You can sell the Car at ${} ".format(output * 1.3))
    else:
        return render_template('index.html')
