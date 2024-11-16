import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
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
    search_query = request.args.get('search')
    category_filter = request.args.get('category')
    location_filter = request.args.get('location')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Construct the query dynamically based on the filters
    query = "SELECT * FROM resources WHERE 1=1"
    params = []

    if search_query:
        query += " AND title LIKE ?"
        params.append('%' + search_query + '%')
    
    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)
    
    if location_filter:
        query += " AND location LIKE ?"
        params.append('%' + location_filter + '%')

    cursor.execute(query, params)
    latest_resources = cursor.fetchall()

    # Fetch top contributors (users who have contributed the most reviews)
    cursor.execute('''
        SELECT users.user_id, users.name, users.profile_image, COUNT(reviews.review_id) as review_count
        FROM users
        JOIN reviews ON users.user_id = reviews.reviewer_id
        GROUP BY users.user_id
        ORDER BY review_count DESC
        LIMIT 5
    ''')
    top_contributors = cursor.fetchall()

    conn.close()

    return render_template('home.html', latest_resources=latest_resources, top_contributors=top_contributors)




init_db()
from werkzeug.security import generate_password_hash
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        location = request.form.get('location')
        profile_image = 'uploads/default-profile.png'

        # Check if the passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Hash the password securely
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

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

            # Insert the new user into the database with the hashed password
            cursor.execute('''INSERT INTO users (name, email, password, location, profile_image)
                              VALUES (?, ?, ?, ?, ?)''',
                           (name, email, hashed_password, location, profile_image))
            conn.commit()
            flash('Registered successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration unsuccessful. Please try again.', 'danger')
            print(f"Error: {e}")  # For debugging purposes
        finally:
            conn.close()

    return render_template('register.html')




from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash  # Import for password verification
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

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

        # Check if user exists and if the password hash matches
        if user and check_password_hash(user[1], password):
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
    cursor.execute('''SELECT reviews.rating, reviews.comment, users.name, reviews.date
                      FROM reviews
                      JOIN users ON reviews.user_id = users.user_id
                      WHERE reviews.user_id = ?
                      ORDER BY reviews.date DESC''', (user_id,))
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

import os

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
        
        # Use os.path.join for cross-platform compatibility
        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        
        # Ensure the upload folder exists
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        # Update the profile image path in the database
        update_profile_image(user_id, f'uploads/{filename}')
        flash('Profile image updated successfully!')
        return redirect(url_for('dashboard'))

    flash('Invalid file type')
    return redirect(url_for('dashboard'))
@app.route('/edit_resource/<int:resource_id>', methods=['GET', 'POST'])
def edit_resource(resource_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the user is the owner of the resource
    cursor.execute("SELECT * FROM resources WHERE resource_id = ? AND user_id = ?", (resource_id, user_id))
    resource = cursor.fetchone()

    if not resource:
        flash("You are not authorized to edit this resource.", "danger")
        conn.close()
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Get updated details from the form
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        availability = request.form.get('availability')
        location = request.form.get('location')

        # Update the resource in the database
        cursor.execute('''
            UPDATE resources
            SET title = ?, description = ?, category = ?, availability = ?, location = ?
            WHERE resource_id = ? AND user_id = ?
        ''', (title, description, category, availability, location, resource_id, user_id))
        
        conn.commit()
        conn.close()
        flash("Resource updated successfully!", "success")
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('edit_resource.html', resource=resource)

# Example route for resource details
@app.route('/resource_details/<int:resource_id>')
def resource_details(resource_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Fetch resource details
    cursor.execute("SELECT * FROM resources WHERE resource_id = ?", (resource_id,))
    resource = cursor.fetchone()

    # Fetch reservations for this resource
    cursor.execute("SELECT start_date, end_date FROM reservations WHERE resource_id = ?", (resource_id,))
    reservations = cursor.fetchall()

    # Convert reservations into a list of dictionaries for JSON serialization
    unavailable_dates = [
        {"start_date": r[0], "end_date": r[1]} for r in reservations if r[0] and r[1]
    ]

    # Fetch reviews with reviewer names
    cursor.execute('''
        SELECT reviews.rating, reviews.comment, users.name, reviews.date
        FROM reviews
        JOIN users ON reviews.reviewer_id = users.user_id
        WHERE reviews.resource_id = ?
    ''', (resource_id,))
    reviews = cursor.fetchall()

    conn.close()

    return render_template(
        'resource_details.html',
        resource=resource,
        unavailable_dates=unavailable_dates,
        reviews=reviews
    )


@app.route('/reserve_resource', methods=['POST'])
def reserve_resource():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    resource_id = request.form.get('resource_id')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    user_id = session['user_id']

    # Save the reservation to the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    if not resource_id or not resource_id.isdigit():
        flash("Invalid resource ID.")
        return redirect(url_for('home'))

    resource_id = int(resource_id)
    try:
        cursor.execute('''
            INSERT INTO reservations (resource_id, user_id, start_date, end_date)
            VALUES (?, ?, ?, ?)
        ''', (resource_id, user_id, start_date, end_date))
        conn.commit()
        flash("Reservation successful!")
    except Exception as e:
        flash(f"Error: {str(e)}")
    finally:
        conn.close()

    return redirect(url_for('resource_details', resource_id=resource_id))
# Flask Route to Handle Reservations
@app.route('/reserve_item/<int:resource_id>', methods=['POST'])
def reserve_item(resource_id):
    if 'user_id' not in session:
        flash("You need to be logged in to make a reservation.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')

    if not start_date or not end_date:
        flash("Please select both start and end dates.")
        return redirect(url_for('resource_details', resource_id=resource_id))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the item is already reserved
    cursor.execute("SELECT availability FROM resources WHERE resource_id = ?", (resource_id,))
    availability = cursor.fetchone()

    if availability and availability[0] == 'Reserved':
        flash("This item is already reserved and cannot be reserved again.")
        conn.close()
        return redirect(url_for('resource_details', resource_id=resource_id))

    # Insert the new reservation into the reservations table
    cursor.execute('''
        INSERT INTO reservations (resource_id, user_id, start_date, end_date)
        VALUES (?, ?, ?, ?)
    ''', (resource_id, user_id, start_date, end_date))

    # Update the availability status of the resource to 'Reserved'
    cursor.execute("UPDATE resources SET availability = 'Reserved' WHERE resource_id = ?", (resource_id,))

    conn.commit()
    conn.close()

    flash("Reservation made successfully!")
    return redirect(url_for('resource_details', resource_id=resource_id))

# Flask Route to Reset Availability
@app.route('/reset_availability/<int:resource_id>', methods=['POST'])
def reset_availability(resource_id):
    # Reset the resource's availability to "Available"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE resources SET availability = 'Available' WHERE resource_id = ?", (resource_id,))
    conn.commit()
    conn.close()
    flash("Resource availability reset to available!")
    return redirect(url_for('resource_details', resource_id=resource_id))

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
        location = request.form.get('location')  # Added location field
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

        # Save the resource with the uploaded image path and other fields, including location
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO resources (user_id, title, description, images, category, availability, location, date_posted)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ''', (user_id, title, description, image_path, category, availability, location))
            conn.commit()
            conn.close()

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
        
        # Get the reviewer_id from the session (current logged-in user)
        reviewer_id = session.get('user_id')

        if not reviewer_id:
            flash("You must be logged in to submit a review.")
            return redirect(url_for('login'))

        # Add the review with the correct resource_id
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reviews (resource_id, user_id, reviewer_id, rating, comment, date)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        ''', (resource_id, reviewer_id, reviewer_id, rating, comment))  # Note: Using `reviewer_id` for `user_id` as well

        conn.commit()
        conn.close()

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
        flash("Please log in to manage your resources.", "danger")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = None

    try:
        # Connect to the database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Check if the logged-in user is the owner of the resource
        cursor.execute("SELECT user_id FROM resources WHERE resource_id = ?", (resource_id,))
        result = cursor.fetchone()

        if result and result[0] == user_id:
            # User is the owner; proceed with deletion
            cursor.execute("DELETE FROM resources WHERE resource_id = ?", (resource_id,))
            conn.commit()
            flash("Resource deleted successfully!", "success")
        else:
            flash("You are not authorized to delete this resource.", "danger")
    except sqlite3.Error as e:
        flash("An error occurred while trying to delete the resource. Please try again later.", "danger")
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    return redirect(url_for('dashboard'))

@app.route('/listings', methods=['GET'])
def listings():
    search_query = request.args.get('search')
    category_filter = request.args.get('category')
    location_filter = request.args.get('location')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Construct the query dynamically based on the filters
    query = "SELECT * FROM resources WHERE 1=1"
    params = []

    if search_query:
        query += " AND title LIKE ?"
        params.append('%' + search_query + '%')
    
    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)
    
    if location_filter:
        query += " AND location LIKE ?"
        params.append('%' + location_filter + '%')

    cursor.execute(query, params)
    all_resources = cursor.fetchall()
    conn.close()

    return render_template('listings.html', all_resources=all_resources)

if __name__ == '__main__':     
    # Run the app on port 5000    
    app.run(port=5000)