from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prescriptions.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Corrected to use consistent path
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    prescriptions = db.relationship('Prescription', backref='patient', lazy=True)

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    file_path = db.Column(db.String(255))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    doctor_name = db.Column(db.String(100))
    medication = db.Column(db.String(100))
    status = db.Column(db.String(20), default='Received')  # Received, Verified, Processing, Ready, Completed
    pharmacy_notes = db.Column(db.Text)
    pickup_date = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notifications = db.relationship('Notification', backref='prescription', lazy=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    prescription_id = db.Column(db.Integer, db.ForeignKey('prescription.id'), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists')
            return redirect(url_for('register'))
        
        new_user = User(
            email=email,
            name=name,
            phone=phone,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    prescriptions = Prescription.query.filter_by(user_id=current_user.id).order_by(Prescription.upload_date.desc()).all()
    unread_notifications = Notification.query.join(Prescription).filter(
        Prescription.user_id == current_user.id,
        Notification.is_read == False
    ).count()
    
    return render_template('dashboard.html', 
                           prescriptions=prescriptions, 
                           unread_notifications=unread_notifications)

@app.route('/upload_prescription', methods=['GET', 'POST'])
@login_required
def upload_prescription():
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'prescription' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['prescription']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Generate a unique filename
            unique_filename = str(uuid.uuid4()) + '_' + secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Save the file
            file.save(file_path)
            
            # Store the relative path in the database (for easier URL generation)
            relative_path = 'uploads/' + unique_filename
            
            # Create new prescription
            new_prescription = Prescription(
                filename=file.filename,
                file_path=relative_path,  # Store the relative path
                doctor_name=request.form.get('doctor_name'),
                medication=request.form.get('medication', 'To be verified'),
                user_id=current_user.id
            )
            
            db.session.add(new_prescription)
            db.session.commit()
            
            # Create notification for the user
            notification = Notification(
                message="Your prescription has been received. We'll begin processing it shortly.",
                prescription_id=new_prescription.id
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Prescription uploaded successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Please upload a JPG, PNG, or PDF.')
    
    return render_template('upload_prescription.html')

@app.route('/view_prescription/<int:prescription_id>')
@login_required
def view_prescription(prescription_id):
    prescription = Prescription.query.get_or_404(prescription_id)
    
    # Security check - ensure user can only view their own prescriptions
    if prescription.user_id != current_user.id:
        flash('Unauthorized access')
        return redirect(url_for('dashboard'))
    
    # Generate the full file path for display
    file_url = url_for('static', filename=prescription.file_path)
    
    notifications = Notification.query.filter_by(
        prescription_id=prescription_id
    ).order_by(Notification.timestamp.desc()).all()
    
    # Mark notifications as read
    for notification in notifications:
        if not notification.is_read:
            notification.is_read = True
    
    db.session.commit()
    
    return render_template('prescription_details.html', 
                          prescription=prescription,
                          file_url=file_url,
                          notifications=notifications)

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.join(Prescription).filter(
        Prescription.user_id == current_user.id
    ).order_by(Notification.timestamp.desc()).all()
    
    # Mark all as read
    for notification in notifications:
        notification.is_read = True
    
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

# API endpoints (for mobile app)
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and check_password_hash(user.password, data.get('password')):
        return jsonify({
            'status': 'success',
            'user_id': user.id,
            'name': user.name
        })
    
    return jsonify({
        'status': 'error',
        'message': 'Invalid credentials'
    }), 401

@app.route('/api/prescriptions', methods=['GET'])
def api_prescriptions():
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User ID required'}), 400
    
    prescriptions = Prescription.query.filter_by(user_id=user_id).order_by(
        Prescription.upload_date.desc()
    ).all()
    
    result = []
    for p in prescriptions:
        result.append({
            'id': p.id,
            'medication': p.medication,
            'status': p.status,
            'upload_date': p.upload_date.strftime('%Y-%m-%d %H:%M'),
            'doctor_name': p.doctor_name
        })
    
    return jsonify({
        'status': 'success',
        'prescriptions': result
    })

# For pharmacy staff (simulated)
@app.route('/staff/login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Hardcoded staff credentials for demo
        if username == 'pharmacy_staff' and password == 'pharmacy123':
            session['is_staff'] = True
            return redirect(url_for('staff_dashboard'))
        
        flash('Invalid credentials')
    
    return render_template('staff_login.html')

@app.route('/staff/dashboard')
def staff_dashboard():
    if not session.get('is_staff'):
        flash('Staff access required')
        return redirect(url_for('staff_login'))
    
    prescriptions = Prescription.query.order_by(
        Prescription.upload_date.desc()
    ).all()
    
    return render_template('staff_dashboard.html', prescriptions=prescriptions)

@app.route('/staff/update_status/<int:prescription_id>', methods=['POST'])
def update_status(prescription_id):
    if not session.get('is_staff'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    prescription = Prescription.query.get_or_404(prescription_id)
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')
    
    # Update prescription status
    prescription.status = new_status
    prescription.pharmacy_notes = notes
    
    # Create notification for the patient
    notification_message = f"Your prescription status has been updated to '{new_status}'."
    if notes:
        notification_message += f" Note: {notes}"
    
    notification = Notification(
        message=notification_message,
        prescription_id=prescription_id
    )
    
    db.session.add(notification)
    db.session.commit()
    
    flash('Prescription status updated!')
    return redirect(url_for('staff_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)