import os
from datetime import datetime
from flask import Flask, redirect, render_template, request, flash, session, url_for
from flask_sqlalchemy import SQLAlchemy
from numpy import datetime_as_string
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__, instance_relative_config=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config.from_mapping(SECRET_KEY='54165465165')
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    name = db.Column(db.String(150))
    records = db.relationship('Record', backref = 'user')

class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key = True)
    date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    entries = db.relationship('Entry', backref = 'record')

class Entry(db.Model):
    __tablename__ = 'entries'
    id = db.Column(db.Integer, primary_key = True)
    value = db.Column(db.Float, nullable=False)
    unity_id = db.Column(db.Integer, db.ForeignKey('unities.id'))
    record_id = db.Column(db.Integer, db.ForeignKey('records.id'))
    def __repr__(self):
        return f'Entry(name={self.value}, unity_id={self.unity_id})'

class Unity(db.Model):
    __tablename__ = 'unities'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), unique=False)
    unity =  db.Column(db.String(32), unique=False)
    def __repr__(self):
        return f'Unity(name="{self.name}", unity="{self.unity}")'

    @classmethod
    def _keys(cls): 
        keys = []
        for key in range(0,17): 
            keys.append(key)
        return keys

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        from_url = request.path
        if 'AUTH' in session:
            return f(*args, **kwargs)
        else:
            if from_url != '/':
                flash('To access {}, login first.'.format(from_url[1:]), 'danger')
            else:
                flash('Precisa fazer o Login primeiro.', 'info')
            return redirect(url_for('login', next=from_url))
    return wrap

@app.route('/', methods=['GET', 'POST'])
def home():
    user_id = session.get('user_id', False)
    print(user_id)
    if not user_id:
        return redirect(url_for('login'))

    records = Record.query.all()
    unities = Unity.query.all()
    dic_unities = {}
    for unity in unities:
        dic_unities[unity.id] = {
        'name': unity.name,
        'unity':  unity.unity
        }

    return render_template('home.html', user = True, unities=dic_unities, records=records)

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    user_id = session.get('user_id', False)
    session['AUTH'] = False
    if user_id == False:
        if request.method == 'POST':
            email = request.form.get('email')
            first_name = request.form.get('firstName')
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')

            user = User.query.filter_by(email=email).first()
            if user:
                flash('Email already exists.', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif len(first_name) < 2:
                flash('First name must be greater than 1 character.', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters.', category='error')
            else:
                new_user = User(email=email, name=first_name, password=generate_password_hash(
                    password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id 
                flash('Account created!', category='success')
                return render_template('home.html')
    else:
        return render_template('sign_up.html', user_id = True)
    return render_template("sign_up.html", user=session['AUTH'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_user = session.get('user_id', False)
    session['AUTH'] = False
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        print(user)
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                #login_user(user, remember=True)
                session['AUTH'] = True
                session['user_id'] = user.id
                return redirect(url_for('home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=session['AUTH'])

@app.route('/logout/')
@login_required
def logout():
    session['AUTH'] = False
    return redirect(url_for('login', user=session['AUTH']))

def db_load_unities():
    print('Preload Unities')
    db.session.add_all([
        Unity(name='Luminosity', unity='Lux'),
        Unity(name='Temperature', unity='ºC'),
        Unity(name='Relative Humidity', unity='%'),
        Unity(name='Electrical Conductivity', unity='mS'),
        Unity(name='pH', unity='pH'),
        Unity(name='Mass', unity='g'),
        Unity(name='Volume', unity='m3'), Unity(name='Volume', unity='dm3'), Unity(name='Volume', unity='cm3'), Unity(name='Volume', unity='mm3'),
        Unity(name='Volume', unity='L'), Unity(name='Volume', unity='dL'), Unity(name='Volume', unity='cL'), Unity(name='Volume', unity='mL'),
    ])
    db.session.commit()

@app.route('/add_data/', methods = ['GET', 'POST'])
def add_data():
    user_id = session.get('user_id', False)
    user = User.query.get(user_id)
    if request.method == 'POST' and user:
        entry_value = request.form.get('entry_value')
        entry_unity = request.form.get('entry_unity')
        print(entry_value) 
    
        if entry_value and entry_unity:
            user = User.query.first()
            unity = Unity.query.filter_by(id=entry_unity).first()
        #
            new_record = Record(user_id=user.id)
            db.session.add(new_record)
            db.session.commit()
        #
            new_entry = Entry(value=entry_value, unity_id=unity.id, record_id=new_record.id)
            db.session.add(new_entry)
            db.session.commit()
        #
            new_record.entries.append(new_entry)
            db.session.commit()    
            flash('Value added!', 'success')

    return redirect(url_for('home'))

if __name__ == '__main__':
    if not os.path.exists('database.sqlite'):
        db.drop_all()
        db.create_all()
        db_load_unities()

        u = User(email='test@email.com', password=generate_password_hash('12345', method='sha256'), name='Debug user')
        db.session.add(u)
        db.session.commit()
    app.run(debug=True, host='0.0.0.0')