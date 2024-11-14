import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
from db import (
    init_db, add_user, authenticate_user, save_resource, get_resource, 
    add_message, get_messages, add_review, get_reviews, get_latest_resources,get_resource_by_id, update_profile_image
)
from db import get_user_by_id, get_user_resources, get_user_messages, get_user_reviews

from werkzeug.security import check_password_hash
#test
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
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


init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        location = request.form.get('location')
        profile_image = 'uploads/default-profile.png'  # Default profile image

        # Connect to the database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            # Check if the email already exists
            cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash('Registration unsuccessful. Email already in use.', 'danger')
                return redirect(url_for('register'))

            # Insert the new user into the database
            cursor.execute('''INSERT INTO users (name, email, password, location, profile_image)
                              VALUES (?, ?, ?, ?, ?)''',
                           (name, email, password, location, profile_image))
            conn.commit()
            flash('Registered successfully!')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration unsuccessful. Please try again.', 'danger')
            print(f"Error: {e}")  # For debugging purposes
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Connect to the database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Check if the user exists in the database
        cursor.execute("SELECT user_id, password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and user[1] == password:  # Check if user exists and the password matches
            session['user_id'] = user[0]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    
    if not user_id:
        return redirect(url_for('login'))

    # Connect to the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Fetch the user's profile information
    cursor.execute("SELECT name, email, location, profile_image FROM users WHERE user_id = ?", (user_id,))
    user_data = cursor.fetchone()

    # Organize the user information into a dictionary
    if user_data:
        user_info = {
            'name': user_data[0],
            'email': user_data[1],
            'location': user_data[2],
            'profile_image': user_data[3] if user_data[3] else 'uploads/default-profile.png'
        }
    else:
        user_info = None

    # Fetch user resources
    cursor.execute("SELECT * FROM resources WHERE user_id = ?", (user_id,))
    user_resources = cursor.fetchall()

    # Fetch user messages
    cursor.execute('''SELECT messages.content, messages.timestamp, users.name
                      FROM messages
                      JOIN users ON messages.sender_id = users.user_id
                      WHERE messages.receiver_id = ?
                      ORDER BY messages.timestamp DESC''', (user_id,))
    user_messages = cursor.fetchall()

    # Fetch user reviews
    cursor.execute('''SELECT reviews.rating, reviews.comment, users.name, reviews.timestamp
                      FROM reviews
                      JOIN users ON reviews.reviewer_id = users.user_id
                      WHERE reviews.user_id = ?
                      ORDER BY reviews.timestamp DESC''', (user_id,))
    user_reviews = cursor.fetchall()

    # Check for new messages
    cursor.execute('''SELECT users.name, messages.timestamp
                      FROM messages
                      JOIN users ON messages.sender_id = users.user_id
                      WHERE messages.receiver_id = ? AND messages.is_read = 0
                      ORDER BY messages.timestamp DESC''', (user_id,))
    new_messages = cursor.fetchall()

    # Close the connection
    conn.close()

    return render_template(
        'dashboard.html',
        user_info=user_info,
        user_resources=user_resources,
        user_messages=user_messages,
        user_reviews=user_reviews,
        new_messages=new_messages
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/update_profile', methods=['POST'])
def update_profile():
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not logged in'})

    data = request.get_json()
    field = data.get('field')
    value = data.get('value')

    if field not in ['name', 'email', 'location']:
        return jsonify({'status': 'error', 'message': 'Invalid field'})

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        cursor.execute(f"UPDATE users SET {field} = ? WHERE user_id = ?", (value, user_id))
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Email already exists'})
    finally:
        conn.close()

@app.route('/upload_profile_image', methods=['POST'])
def upload_profile_image():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Check if a file is uploaded
    if 'profile_image' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))

    file = request.files['profile_image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Update the profile image path in the database
        update_profile_image(user_id, f'uploads/{filename}')
        flash('Profile image updated successfully!')
        return redirect(url_for('dashboard'))

    flash('Invalid file type')
    return redirect(url_for('dashboard'))
@app.route('/resource_details/<int:resource_id>')
def resource_details(resource_id):
    # Fetch resource details using the new function
    resource = get_resource_by_id(resource_id)
    
    if not resource:
        return "Resource not found", 404  # Handle the case where the resource is not found

    # Fetch reviews for the resource's owner
    user_id = resource[1]  # Assuming user_id is the second element (index 1)
    reviews = get_reviews(user_id)

    return render_template('resource_details.html', resource=resource, reviews=reviews)

def get_resources():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources")
    resources = cursor.fetchall()
    conn.close()

    # Format the date_posted to MM-DD-YYYY
    formatted_resources = []
    for resource in resources:
        date_posted = datetime.strptime(resource[7], '%Y-%m-%d %H:%M:%S')
        formatted_date = date_posted.strftime('%m-%d-%Y')  # Format date as MM-DD-YYYY
        formatted_resources.append(resource[:7] + (formatted_date,))  # Replace date_posted with formatted_date

    return formatted_resources

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
        file = request.files.get('image')  # Changed 'images' to 'image'

        # Ensure the upload directory exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        # Handle image upload
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_path = f'uploads/{filename}'  # Save relative path
        else:
            flash("Please upload a valid JPG image.")
            return redirect(url_for('add_resource'))

        # Save the resource with the uploaded image path and other fields
        try:
            save_resource(user_id, title, description, image_path, category, availability)
            flash("Resource added successfully!")
            return redirect(url_for('home'))
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('add_resource'))
    
    return render_template('add_resource.html')

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Fetch all users except the current user
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, name FROM users WHERE user_id != ?", (user_id,))
    users = cursor.fetchall()

    # Fetch messages for the current user
    cursor.execute('''SELECT messages.content, messages.timestamp, users.name
                      FROM messages
                      JOIN users ON messages.sender_id = users.user_id
                      WHERE messages.receiver_id = ?
                      ORDER BY messages.timestamp DESC''', (user_id,))
    messages = cursor.fetchall()

    # Mark all messages as read
    cursor.execute("UPDATE messages SET is_read = 1 WHERE receiver_id = ?", (user_id,))
    conn.commit()
    conn.close()

    return render_template('messages.html', users=users, messages=messages)


@app.route('/send_message', methods=['POST'])
def send_message():
    sender_id = session.get('user_id')
    if not sender_id:
        return redirect(url_for('login'))

    recipient_id = request.form.get('recipient_id')
    message_content = request.form.get('message')

    if recipient_id and message_content:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO messages (sender_id, receiver_id, content, timestamp)
                          VALUES (?, ?, ?, datetime('now'))''',
                       (sender_id, recipient_id, message_content))
        conn.commit()
        conn.close()
        flash('Message sent successfully!')

    return redirect(url_for('messages'))

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

from flask import request, redirect, url_for, flash, session
from db import add_review, get_user_id_by_resource_id

@app.route('/add_review/<int:resource_id>', methods=['POST'])
def add_review_route(resource_id):
    # Extract form data
    rating = request.form.get('rating')
    comment = request.form.get('comment')

    # Ensure both fields are filled in
    if not rating or not comment:
        flash("Both rating and comment are required.")
        return redirect(url_for('resource_details', resource_id=resource_id))

    try:
        # Convert the rating to an integer
        rating = int(rating)
        
        # Ensure the rating is between 1 and 5
        if rating < 1 or rating > 5:
            flash("Rating must be between 1 and 5.")
            return redirect(url_for('resource_details', resource_id=resource_id))
        
        # Get the user_id for the resource (user being reviewed)
        user_id = get_user_id_by_resource_id(resource_id)
        # Get the reviewer_id from the session (current logged-in user)
        reviewer_id = session.get('user_id')

        if not reviewer_id:
            flash("You must be logged in to submit a review.")
            return redirect(url_for('login'))

        # Call the add_review function from db.py
        add_review(user_id, reviewer_id, rating, comment)
        flash("Review submitted successfully.")
    except ValueError:
        flash("Invalid input for rating. Please enter a number between 1 and 5.")
    except Exception as e:
        flash("An error occurred: " + str(e))

    # Redirect back to the correct resource details page
    return redirect(url_for('resource_details', resource_id=resource_id))

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
