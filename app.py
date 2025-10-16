from flask import Flask, render_template, request, send_file, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import pandas as pd
from io import BytesIO, StringIO
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import csv
import json
import os
from datetime import datetime

app = Flask(__name__)

# --- Authentication Configuration ---
app.config['SECRET_KEY'] = 'a_very_secure_and_random_secret_key_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Model (User) ---
class User(db.Model):
    """Database model for storing user credentials and roles."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    # Role differentiates access: 'student' or 'admin'
    role = db.Column(db.String(10), nullable=False) 

    def set_password(self, password):
        """Hashes and stores the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks the provided password against the stored hash."""
        return check_password_hash(self.password_hash, password)

# --- Helper Function to Ensure Login/Role ---
def login_required(role=None):
    """
    Decorator to check if a user is logged in and, optionally, has a specific role.
    """
    def wrapper(func):
        def inner(*args, **kwargs):
            if 'logged_in' not in session or not session['logged_in']:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            
            if role and session['role'] != role:
                flash(f'Access denied. Only {role.capitalize()} users are allowed.', 'danger')
                # Redirect non-authorized users to their home dashboard
                return redirect(url_for(f"{session['role']}_dashboard"))

            return func(*args, **kwargs)
        inner.__name__ = func.__name__ # Needed for Flask routing
        return inner
    return wrapper

# --- Setup: Creates DB file and default users on first run ---
@app.before_request
def create_db_and_users():
    """Initializes the database and adds default users for testing."""
    try:
        db.create_all()
        
        # Create default Admin user
        if User.query.filter_by(username='admin').first() is None:
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin123') # CHANGE THIS PASSWORD!
            db.session.add(admin_user)
        
        # Create default Student user
        if User.query.filter_by(username='student1').first() is None:
            student_user = User(username='student1', role='student')
            student_user.set_password('student123') # CHANGE THIS PASSWORD!
            db.session.add(student_user)

        db.session.commit()
        print("Database initialized and default users created.")
    except Exception as e:
        print(f"Error during database setup: {e}")

# --- Authentication Routes ---

@app.route('/', methods=['GET'])
def home():
    """Default route: Redirects logged-in users to their dashboard, otherwise to login."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session management."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Successful login
            session['logged_in'] = True
            session['username'] = user.username
            session['role'] = user.role 
            
            #flash(f'Welcome, {user.username.capitalize()}!', 'success')
            
            # Role-based redirection
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        
        # Validation
        if not username or not password or not confirm_password or not role:
            flash('All fields are required.', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('signup.html')
        
        if role not in ['student', 'admin']:
            flash('Please select a valid role.', 'error')
            return render_template('signup.html')
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('signup.html')
        
        # Create new user
        try:
            new_user = User(username=username, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('signup.html')
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('form_data', None)
    session.pop('saved_timetables', None)
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('login'))

# --- SECURED PAGES ---

@app.route('/student_dashboard')
@login_required(role='student')
def student_dashboard():
    """Student access point (e.g., to view the timetable)."""
    saved_timetables = get_saved_timetables()
    return render_template('student_dashboard.html', 
                         username=session['username'].capitalize(),
                         timetables=saved_timetables)

@app.route('/admin_dashboard')
@login_required(role='admin')
def admin_dashboard():
    """Admin access point for timetable generation."""
    # Clear any previous session data for a fresh start
    session.pop('form_data', None)
    # Check if we need to clear all data (from Create New Timetable button)
    clear_data = request.args.get('clear', 'false') == 'true'
    return render_template('admin.html', 
                         username=session['username'].capitalize(),
                         clear_data=clear_data)

# --- Timetable Application Code ---

# Define slot timings
SLOTS = [
    "8:00 - 8:50", "8:50 - 9:40", "9:40 - 10:30",
    "10:45 - 11:35", "11:35 - 12:25", "12:25 - 1:15",
    "1:15 - 2:05", "2:05 - 2:55", "2:55 - 3:45", "3:45 - 4:35"
]

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

# Store last generated timetable (for downloads)
last_generated = {}

# Store multiple timetables in session
def get_saved_timetables():
    return session.get('saved_timetables', [])

def save_timetable(timetable_data):
    saved_timetables = get_saved_timetables()
    # Add timestamp and ID to the timetable
    timetable_data['id'] = len(saved_timetables) + 1
    timetable_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    saved_timetables.append(timetable_data)
    session['saved_timetables'] = saved_timetables
    return timetable_data['id']

def get_timetable_by_id(timetable_id):
    saved_timetables = get_saved_timetables()
    for timetable in saved_timetables:
        if timetable['id'] == timetable_id:
            return timetable
    return None

@app.route('/generate', methods=['POST'])
@login_required(role='admin')
def generate():
    global last_generated

    dept = request.form.get('department')
    semester = request.form.get('semester')
    classroom = request.form.get('classroom')
    block = request.form.get('block')

    # Retrieve all input fields
    course_codes = request.form.getlist('course_code[]')
    subjects = request.form.getlist('subject_name[]')
    faculties = request.form.getlist('faculty_name[]')
    faculty_ids = request.form.getlist('faculty_id[]')
    slots_per_week = request.form.getlist('slots_per_week[]')
    consecutive_flags = request.form.getlist('consecutive[]')
    consecutive_counts = request.form.getlist('consecutive_count[]')

    # Store form data in session for persistence
    form_data = {
        'department': dept,
        'semester': semester,
        'block': block,
        'classroom': classroom,
        'courses': []
    }
    
    # Add course data to session
    for j in range(len(course_codes)):
        course_data = {
            'course_code': course_codes[j],
            'subject_name': subjects[j],
            'faculty_name': faculties[j],
            'faculty_id': faculty_ids[j],
            'slots_per_week': slots_per_week[j],
            'consecutive': consecutive_flags[j],
            'consecutive_count': consecutive_counts[j] if j < len(consecutive_counts) else ''
        }
        form_data['courses'].append(course_data)
    
    session['form_data'] = form_data

    # Validate slots per week values (should be 1-4 only)
    for i, slots in enumerate(slots_per_week):
        if not slots.isdigit() or int(slots) not in [1, 2, 3, 4]:
            return render_template('admin.html', 
                                 error=f"Invalid slots per week value: {slots}. Must be between 1-4.", 
                                 prev_data=form_data,
                                 username=session['username'].capitalize())

    # Validate total slots (server-side validation) - max 50 classes
    total_slots_requested = sum(int(slots) for slots in slots_per_week)
    if total_slots_requested > 50:
        return render_template('admin.html', 
                             error=f"Total slots requested ({total_slots_requested}) exceeds maximum allowed (50)! Please reduce the number of subjects or slots.", 
                             prev_data=form_data,
                             username=session['username'].capitalize())

    # Validate that we have at least one course
    if len(course_codes) == 0 or not any(course_codes):
        return render_template('admin.html', 
                             error="Please add at least one course to generate timetable.", 
                             prev_data=form_data,
                             username=session['username'].capitalize())

    # Validate consecutive slots logic
    for i in range(len(consecutive_flags)):
        if consecutive_flags[i] == "Yes" and (not consecutive_counts[i] or consecutive_counts[i] == ""):
            return render_template('admin.html',
                                 error=f"Please select consecutive count for {subjects[i]} since consecutive slots are requested.",
                                 prev_data=form_data,
                                 username=session['username'].capitalize())

    # Empty timetable structure
    timetable = {day: [""] * len(SLOTS) for day in DAYS}
    assigned_slots = {}  # Prevent faculty time clashes
    subject_day_allocation = {}  # Track which subjects are allocated to which days

    # ---------------- GENERATE TIMETABLE ----------------
    for i in range(len(subjects)):
        subject = subjects[i]
        faculty = faculties[i]
        faculty_id = faculty_ids[i]
        total_slots = int(slots_per_week[i])
        consecutive = consecutive_flags[i]
        consecutive_count = int(consecutive_counts[i]) if consecutive_counts[i] and consecutive_counts[i].isdigit() else 0

        subject_tag = f"{subject} ({faculty})"
        slots_allocated = 0
        attempts = 0
        
        # Initialize subject tracking
        if subject not in subject_day_allocation:
            subject_day_allocation[subject] = {day: 0 for day in DAYS}

        # Allocate consecutive pairs first
        if consecutive == "Yes" and consecutive_count > 0:
            for _ in range(consecutive_count):
                if slots_allocated + 2 > total_slots:
                    break  # Don't exceed total slots

                success = False
                for _ in range(400):  # Increased attempts for better allocation
                    day = random.choice(DAYS)
                    
                    # Check if this subject already has classes on this day
                    # If so, skip to avoid multiple sessions on same day
                    if subject_day_allocation[subject][day] > 0:
                        continue
                        
                    start_slot = random.randint(0, len(SLOTS) - 2)

                    pair_free = all(
                        timetable[day][start_slot + j] == "" and
                        (faculty_id not in assigned_slots or (day, start_slot + j) not in assigned_slots[faculty_id])
                        for j in range(2)
                    )

                    if pair_free:
                        for j in range(2):
                            timetable[day][start_slot + j] = subject_tag
                            assigned_slots.setdefault(faculty_id, []).append((day, start_slot + j))
                        slots_allocated += 2
                        subject_day_allocation[subject][day] += 2  # Track allocation
                        success = True
                        break

                if not success:
                    print(f"⚠️ Could not allocate consecutive pair for {subject}")

        # Allocate remaining random slots - ensure no same subject on same day
        while slots_allocated < total_slots and attempts < 1000:
            attempts += 1
            day = random.choice(DAYS)
            slot_index = random.randint(0, len(SLOTS) - 1)

            # Check if subject already has classes on this day
            if subject_day_allocation[subject][day] > 0:
                continue
                
            if timetable[day][slot_index] != "":
                continue
            if faculty_id in assigned_slots and (day, slot_index) in assigned_slots[faculty_id]:
                continue

            timetable[day][slot_index] = subject_tag
            assigned_slots.setdefault(faculty_id, []).append((day, slot_index))
            subject_day_allocation[subject][day] += 1  # Track allocation
            slots_allocated += 1

    # If we still have slots to allocate (due to constraints), try more flexible allocation
    for i in range(len(subjects)):
        subject = subjects[i]
        faculty = faculties[i]
        faculty_id = faculty_ids[i]
        total_slots = int(slots_per_week[i])
        
        subject_tag = f"{subject} ({faculty})"
        
        # Count currently allocated slots
        current_slots = 0
        for day in DAYS:
            for slot in range(len(SLOTS)):
                if timetable[day][slot] == subject_tag:
                    current_slots += 1
        
        # Allocate any remaining slots with relaxed constraints
        while current_slots < total_slots:
            day = random.choice(DAYS)
            slot_index = random.randint(0, len(SLOTS) - 1)
            
            if timetable[day][slot_index] == "":
                if faculty_id not in assigned_slots or (day, slot_index) not in assigned_slots[faculty_id]:
                    timetable[day][slot_index] = subject_tag
                    assigned_slots.setdefault(faculty_id, []).append((day, slot_index))
                    current_slots += 1

    # Add "Break" after 3rd slot visually
    display_slots = []
    for i, s in enumerate(SLOTS):
        if i == 3:
            display_slots.append("Break")
        display_slots.append(s)

    adjusted_timetable = {}
    for day, periods in timetable.items():
        new_periods = []
        for i, p in enumerate(periods):
            if i == 3:
                new_periods.append("Break")
            new_periods.append(p)
        adjusted_timetable[day] = new_periods

    # Course summary for display
    course_summary = list(zip(course_codes, subjects, faculties))

    # Save to memory (for download) - Include Saturday in downloads
    timetable_data = {
        "dept": dept,
        "semester": semester,
        "classroom": classroom,
        "block": block,
        "slots": display_slots,
        "timetable": adjusted_timetable,
        "course_summary": course_summary,
        "total_slots": total_slots_requested,
        "courses": form_data['courses']
    }

    # Save to global variable for downloads
    last_generated = timetable_data
    
    # Also save to session for persistence
    timetable_id = save_timetable(timetable_data)

    # Render output page with previous data
    return render_template(
        'timetable.html',
        dept=dept,
        semester=semester,
        classroom=classroom,
        block=block,
        slots=display_slots,
        timetable=adjusted_timetable,
        course_summary=course_summary,
        total_slots=total_slots_requested,
        prev_data=form_data,
        timetable_id=timetable_id,
        username=session['username'].capitalize()
    )


@app.route('/saved_timetables')
@login_required()
def saved_timetables():
    """Display all saved timetables"""
    saved_timetables = get_saved_timetables()
    return render_template('saved_timetables.html', 
                         timetables=saved_timetables,
                         username=session['username'].capitalize(),
                         role=session['role'])


@app.route('/view_timetable/<int:timetable_id>')
@login_required()
def view_timetable(timetable_id):
    """View a specific saved timetable"""
    timetable = get_timetable_by_id(timetable_id)
    if not timetable:
        return render_template('error.html', error="Timetable not found"), 404
    
    return render_template(
        'timetable.html',
        dept=timetable['dept'],
        semester=timetable['semester'],
        classroom=timetable['classroom'],
        block=timetable['block'],
        slots=timetable['slots'],
        timetable=timetable['timetable'],
        course_summary=timetable['course_summary'],
        total_slots=timetable['total_slots'],
        prev_data={
            'department': timetable['dept'],
            'semester': timetable['semester'],
            'block': timetable['block'],
            'classroom': timetable['classroom'],
            'courses': timetable.get('courses', [])
        },
        timetable_id=timetable_id,
        from_saved=True,
        username=session['username'].capitalize(),
        role=session['role']
    )


@app.route('/delete_timetable/<int:timetable_id>')
@login_required(role='admin')
def delete_timetable(timetable_id):
    """Delete a saved timetable"""
    saved_timetables = get_saved_timetables()
    saved_timetables = [t for t in saved_timetables if t['id'] != timetable_id]
    session['saved_timetables'] = saved_timetables
    flash('Timetable deleted successfully.', 'success')
    return redirect(url_for('saved_timetables'))


@app.route('/restore_form_data')
@login_required(role='admin')
def restore_form_data():
    """Restore the last form data from session"""
    form_data = session.get('form_data')
    if form_data:
        return render_template('admin.html', 
                             prev_data=form_data,
                             username=session['username'].capitalize())
    else:
        return redirect(url_for('admin_dashboard'))


# ---------------- DOWNLOAD PDF ----------------
@app.route('/download_pdf', methods=['POST'])
@login_required()
def download_pdf():
    if not last_generated:
        return "No timetable generated yet."

    data = last_generated
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph(
        f"<b>Department:</b> {data['dept']} &nbsp;&nbsp;&nbsp; "
        f"<b>Semester:</b> {data['semester']} &nbsp;&nbsp;&nbsp; "
        f"<b>Classroom:</b> {data['classroom']} &nbsp;&nbsp;&nbsp; "
        f"<b>Block:</b> {data['block']} &nbsp;&nbsp;&nbsp; "
        f"<b>Total Slots:</b> {data.get('total_slots', 'N/A')}",
        styles['Normal']
    ))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Generated Timetable</b>", styles['Title']))
    elements.append(Spacer(1, 12))

    # Timetable table with slot numbering and Saturday
    table_data = [["Day/Time"] + data["slots"]]
    
    # Add slot numbering row
    slot_row = ["Slot"]
    slot_counter = 1
    for slot in data["slots"]:
        if "Break" in slot:
            slot_row.append("Break")
        else:
            slot_row.append(f"Slot {slot_counter}")
            slot_counter += 1
    table_data.append(slot_row)
    
    # Add Monday to Friday
    for day, periods in data["timetable"].items():
        table_data.append([day] + periods)
    
    # Add Saturday row
    saturday_row = ["Saturday"]
    for slot in data["slots"]:
        if "Break" in slot:
            saturday_row.append("Break")
        else:
            saturday_row.append("")
    table_data.append(saturday_row)

    table = Table(table_data, repeatRows=2)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 1), colors.lightblue),
        ('BACKGROUND', (0, 2), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
        ('FONTNAME', (0, 2), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, -1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<b>Course Summary</b>", styles['Heading2']))
    elements.append(Spacer(1, 6))

    # Course summary table
    summary_data = [["Course Code", "Subject Name", "Faculty Name"]]
    for code, subject, faculty in data["course_summary"]:
        summary_data.append([code, subject, faculty])

    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"timetable_{data['dept']}_{data['semester']}.pdf", mimetype='application/pdf')


# ---------------- DOWNLOAD CSV ----------------
@app.route('/download_csv')
@login_required()
def download_csv():
    if not last_generated:
        return "No timetable generated yet."

    data = last_generated
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Department:", data['dept'], "Semester:", data['semester'], "Classroom:", data['classroom'], "Block:", data['block']])
    writer.writerow([])
    writer.writerow(["Day/Time"] + data["slots"])

    for day, periods in data["timetable"].items():
        writer.writerow([day] + periods)

    # Add Saturday row
    saturday_row = ["Saturday"]
    for slot in data["slots"]:
        if "Break" in slot:
            saturday_row.append("Break")
        else:
            saturday_row.append("")
    writer.writerow(saturday_row)

    writer.writerow([])
    writer.writerow(["Course Summary"])
    writer.writerow(["Course Code", "Subject Name", "Faculty Name"])
    for code, subject, faculty in data["course_summary"]:
        writer.writerow([code, subject, faculty])

    buffer.seek(0)
    return send_file(BytesIO(buffer.getvalue().encode()), as_attachment=True, download_name=f"timetable_{data['dept']}_{data['semester']}.csv", mimetype='text/csv')


# ---------------- DOWNLOAD JSON ----------------
@app.route('/download_json')
@login_required()
def download_json():
    if not last_generated:
        return "No timetable generated yet."

    data = last_generated
    json_data = json.dumps(data, indent=2)
    buffer = BytesIO(json_data.encode())
    return send_file(buffer, as_attachment=True, download_name=f"timetable_{data['dept']}_{data['semester']}.json", mimetype='application/json')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)