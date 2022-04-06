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