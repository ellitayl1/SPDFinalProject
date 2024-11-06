import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import sqlite3
from db import (
    init_db, add_user, authenticate_user, save_resource, get_resource, 
    add_message, get_messages, add_review, get_reviews, get_latest_resources
)
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg'}

# Initialize the database
init_db()

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
# Initialize the database
init_db()



@app.route('/')
def home():
    latest_resources = get_latest_resources()
    return render_template('home.html', latest_resources=latest_resources)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = authenticate_user(email, password)
        if user:
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        try:
            add_user(name, email, password)
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email is already registered')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM resources WHERE user_id = ?", (user_id,))
    user_resources = cursor.fetchall()
    user_messages = get_messages(user_id)
    user_reviews = get_reviews(user_id)
    
    conn.close()
    return render_template('dashboard.html', user_resources=user_resources, user_messages=user_messages, user_reviews=user_reviews)

@app.route('/resource/<int:resource_id>')
def resource_details(resource_id):
    resource = get_resource(resource_id)
    reviews = get_reviews(resource[1])  # Fetch reviews for the resource owner (user_id)
    return render_template('resource_details.html', resource=resource, reviews=reviews)

import os
from werkzeug.utils import secure_filename

@app.route('/add_resource', methods=['GET', 'POST'])
def add_resource():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        availability = request.form.get('availability')
        user_id = session['user_id']
        file = request.files['images']

        # Ensure the upload directory exists
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Handle image upload
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            image_path = os.path.join('uploads', filename)  # Save relative path
        else:
            flash("Please upload a valid JPG image.")
            return redirect(url_for('add_resource'))

        # Save the resource with the uploaded image path and other fields
        try:
            save_resource(user_id, title, description, image_path, category, availability)
            flash("Resource added successfully!")
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('add_resource'))
    
    return render_template('add_resource.html')

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        content = request.form['content']
        
        add_message(user_id, receiver_id, content)
        flash("Message sent successfully!")
        return redirect(url_for('messages'))
    
    user_messages = get_messages(user_id)
    return render_template('messages.html', user_messages=user_messages)

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Only delete if the user is involved in the message (sender or receiver)
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM messages WHERE message_id = ? AND (sender_id = ? OR receiver_id = ?)",
                   (message_id, user_id, user_id))
    conn.commit()
    conn.close()
    
    flash("Message deleted successfully!")
    return redirect(url_for('messages'))

@app.route('/add_review/<int:user_id>', methods=['POST'])
def add_review_route(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    reviewer_id = session['user_id']
    rating = request.form['rating']
    comment = request.form['comment']
    
    add_review(user_id, reviewer_id, rating, comment)
    flash("Review added successfully!")
    return redirect(url_for('resource_details', resource_id=user_id))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/delete_resource/<int:resource_id>', methods=['POST'])
def delete_resource(resource_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the logged-in user is the owner of the resource
    cursor.execute("SELECT user_id FROM resources WHERE resource_id = ?", (resource_id,))
    result = cursor.fetchone()

    if result and result[0] == user_id:
        # User is the owner; proceed with deletion
        cursor.execute("DELETE FROM resources WHERE resource_id = ?", (resource_id,))
        conn.commit()
        flash("Resource deleted successfully!")
    else:
        flash("You are not authorized to delete this resource.")

    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
