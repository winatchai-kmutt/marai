from flask import Flask, render_template, request, redirect, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
import secrets
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'maraimanageresidence@gmail.com'
app.config['MAIL_USERNAME'] = 'maraimanageresidence@gmail.com'
app.config['MAIL_PASSWORD'] = 'ylbhjjqvhtxtngkx'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    verified = db.Column(db.Boolean, default=False)

# Define the Petition model
class Petition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number_room = db.Column(db.String(10))
    petition_type = db.Column(db.String(50))
    petition_detail = db.Column(db.Text)
    petition_status = db.Column(db.String(20))


with app.app_context():
    db.create_all()

from flask_mail import Mail, Message
mail = Mail(app)

@app.route('/')
def home():
    token = request.cookies.get('token')
    if token:
        try:
            # Verify the JWT token
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            email = session.get('email')
            return render_template('home.html', email=email)
        except jwt.ExpiredSignatureError:
            return redirect('/login')
        except jwt.DecodeError:
            return redirect('/login')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='scrypt')

        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        token = jwt.encode({'user_id': new_user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        verification_link = request.host_url + 'verify/' + token
        message = f"Please click the following link to verify your email: {verification_link}"
        send_email(email, "Email Verification", message)

        return redirect('/wait_verify')

    return render_template('register.html')

@app.route('/wait_verify')
def wait_verify():
    return render_template('wait_verify.html')

@app.route('/verify/<token>', methods=['GET'])
def verify(token):
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
        user = User.query.get(user_id)

        if user:
            user.verified = True
            db.session.commit()
            return redirect('/register_completed')
        else:
            return jsonify({'message': 'Invalid token'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'})
    except jwt.DecodeError:
        return jsonify({'message': 'Invalid token'})

@app.route('/register_completed')
def register_completed():
    return render_template('register_completed.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password) and user.verified:
            # Create a JWT token
            token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                               app.config['SECRET_KEY'])

            session['email'] = email

            response = redirect('https://mydormitory25.000webhostapp.com/testphp/index.php?fbclid=IwAR3bkMabWP7SoYHJtXSEhqLu_mDKvTIibwtQirGxqg8kU-O7bEeDaX9t2tc')
            response.set_cookie('token', token)
            return response

        return jsonify({'message': 'Invalid email or password'})

    return render_template('login.html')

@app.route('/logout')
def logout():
    response = redirect('/login')
    response.delete_cookie('token')
    session.pop('email', None)
    return response

@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate a reset password token
            token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
            reset_link = request.host_url + 'update_password/' + token
            message = f"Please click the following link to reset your password: {reset_link}"
            send_email(email, "Password Reset", message)
        
        return render_template('forget_password.html', message='If the provided email exists in our records, a password reset link will be sent.')

    return render_template('forget_password.html')

@app.route('/update_password/<token>', methods=['GET', 'POST'])
def update_password(token):
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
        user = User.query.get(user_id)
        
        if user:
            if request.method == 'POST':
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                
                if password == confirm_password:
                    # Update the user's password
                    user.password = generate_password_hash(password, method='scrypt')
                    db.session.commit()
                    
                    return redirect('/login')
                else:
                    return jsonify({'message': 'Passwords do not match.'})
        
            return render_template('update_password.html', token=token)

        else:
            return jsonify({'message': 'Invalid token'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'})
    except jwt.DecodeError:
        return jsonify({'message': 'Invalid token'})




# Route for displaying the petitions
@app.route('/petitions')
def petitions():
    petitions = Petition.query.all()
    return render_template('petition_page.html', petitions=petitions)

# Route for updating the petition status
@app.route('/petitions/update_status', methods=['POST'])
def update_status():
    peition_id = request.form.get('petition_id')
    new_status = request.form.get('new_status')
    petition = Petition.query.get(peition_id)
    if petition:
        petition.petition_status = new_status
        db.session.commit()
    
    return redirect('/petitions')


def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)

@app.route('/petition_upload', methods=['GET'])
def petition():
    return render_template('petition_upload.html')

@app.route('/bill_upload', methods=['GET'])
def upload():
    return render_template('upload_bill.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')