import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import hashlib
import os
# Initialize the database and tables
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        profile_image TEXT,
                        location TEXT
                      )''')
    
    # Create Resources table
    cursor.execute('''CREATE TABLE IF NOT EXISTS resources (
                        resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        images TEXT,
                        category TEXT,
                        availability TEXT,
                        date_posted TEXT NOT NULL,
                        location TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(user_id)
                      )''')
    
    # Create Messages table
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER NOT NULL,
                        receiver_id INTEGER NOT NULL,
                        content TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        is_read INT DEFAULT 0,
                        FOREIGN KEY (sender_id) REFERENCES users(user_id),
                        FOREIGN KEY (receiver_id) REFERENCES users(user_id)
                      )''')
                   
    # Create Reviews table
    cursor.execute('''CREATE TABLE IF NOT EXISTS reviews (
    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NULL,
    user_id INTEGER NOT NULL,
    reviewer_id INTEGER, 
    rating INTEGER NOT NULL,
    comment TEXT,
    date TEXT,
    FOREIGN KEY (resource_id) REFERENCES resources(resource_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (reviewer_id) REFERENCES users(user_id)
);
''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS reservations (
            reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            FOREIGN KEY (resource_id) REFERENCES resources(resource_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )''')
  
    conn.commit()
    conn.close()
def update_resource_availability(resource_id, status):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE resources SET availability = ? WHERE resource_id = ?", (status, resource_id))
    conn.commit()
    conn.close()

# Function to hash a password with a salt
def hash_password(password):
    salt = os.urandom(16).hex()  # Generate a random 16-byte salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return f"{salt}${hashed_password}"

# Function to add a new user with hashed password
def add_user(name, email, password, profile_image=None, location=None):
    hashed_password = hash_password(password)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (name, email, password, profile_image, location) VALUES (?, ?, ?, ?, ?)",
                   (name, email, hashed_password, profile_image, location))
    conn.commit()
    conn.close()

# Function to verify a password
def verify_password(stored_password, provided_password):
    salt, hashed_password = stored_password.split('$')  # Split the stored salt and hash
    salted_password = salt + provided_password
    return hashlib.sha256(salted_password.encode('utf-8')).hexdigest() == hashed_password

# Function to authenticate a user
def authenticate_user(email, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(user[3], password):
        return user
    else:
        return None
# Function to save a new resource
def save_resource(user_id, title, description, images, category, availability):
    if not title or not user_id:
        raise ValueError("Title and user_id are required fields.")
    date_posted = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO resources (user_id, title, description, images, category, availability, date_posted) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (user_id, title, description, images, category, availability, date_posted))
    conn.commit()
    conn.close()

# Function to get a resource by ID
def get_resource(resource_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources WHERE resource_id = ?", (resource_id,))
    resource = cursor.fetchone()
    conn.close()
    return resource

def get_latest_resources(limit=5):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources ORDER BY date_posted DESC LIMIT ?", (limit,))
    latest_resources = cursor.fetchall()
    conn.close()
    return latest_resources
def update_profile_image(user_id, image_path):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET profile_image = ? WHERE user_id = ?", (image_path, user_id))
    conn.commit()
    conn.close()
# Function to add a new message
def add_message(sender_id, receiver_id, content):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %I:%M %p')
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)",
                   (sender_id, receiver_id, content, timestamp))
    conn.commit()
    conn.close()

# Function to get messages for a user
def get_messages(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
    messages = cursor.fetchall()
    conn.close()
    return messages




def add_review(user_id, reviewer_id, rating, comment):
    # Connect to the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Insert the review into the reviews table
    try:
        cursor.execute(
            '''INSERT INTO reviews (user_id, reviewer_id, rating, comment, date) 
               VALUES (?, ?, ?, ?, ?)''',
            (user_id, reviewer_id, rating, comment, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
    except Exception as e:
        print("Error inserting review:", e)
    finally:
        conn.close()


def get_resource_by_id(resource_id):
    # Connect to the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Query to get the resource details by ID
    cursor.execute("SELECT * FROM resources WHERE resource_id = ?", (resource_id,))
    resource = cursor.fetchone()
    conn.close()

    # Return the resource details
    return resource

def get_user_id_by_resource_id(resource_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM resources WHERE resource_id = ?", (resource_id,))
    user_id = cursor.fetchone()
    conn.close()

    return user_id[0] if user_id else None

def get_user_resources(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources WHERE user_id = ?", (user_id,))
    resources = cursor.fetchall()
    conn.close()
    return resources


def get_user_messages(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
    messages = cursor.fetchall()
    conn.close()
    return messages

def get_user_reviews(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reviews WHERE user_id = ?", (user_id,))
    reviews = cursor.fetchall()
    conn.close()
    return reviews

def get_user_by_id(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    # Return user data as a dictionary if needed
    if user:
        return {
            'user_id': user[0],
            'name': user[1],
            'email': user[2],
            'profile_image': user[4],  # Adjust indexes based on your table
            'location': user[5]
        }
    return None

# Function to get reviews for a specific user or resource
def get_reviews(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Fetch the reviews along with the reviewer's name
    cursor.execute('''
        SELECT reviews.review_id, reviews.rating, reviews.comment, reviews.timestamp, users.name
        FROM reviews
        JOIN users ON reviews.reviewer_id = users.user_id
        WHERE reviews.user_id = ?
    ''', (user_id,))
    reviews = cursor.fetchall()
    conn.close()

    # Format the timestamp to MM-DD-YYYY hh:mm AM/PM
    formatted_reviews = []
    for review in reviews:
        try:
            # Ensure the timestamp is a string before parsing
            timestamp = str(review[3])  # Assuming timestamp is the 4th element (index 3)
            # Parse the timestamp
            timestamp_parsed = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            # Format the timestamp to MM-DD-YYYY hh:mm AM/PM
            formatted_timestamp = timestamp_parsed.strftime('%m-%d-%Y %I:%M %p')
            # Append the formatted review with the reviewer's name
            formatted_reviews.append((review[0], review[1], review[2], formatted_timestamp, review[4]))
        except ValueError:
            # In case of an error, append the original review data
            formatted_reviews.append(review)

    return formatted_reviews
