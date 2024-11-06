import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

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
                        FOREIGN KEY (user_id) REFERENCES users(user_id)
                      )''')
    
    # Create Messages table
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER NOT NULL,
                        receiver_id INTEGER NOT NULL,
                        content TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (sender_id) REFERENCES users(user_id),
                        FOREIGN KEY (receiver_id) REFERENCES users(user_id)
                      )''')
    
    # Create Reviews table
    cursor.execute('''CREATE TABLE IF NOT EXISTS reviews (
                        review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        reviewer_id INTEGER NOT NULL,
                        rating INTEGER NOT NULL,
                        comment TEXT,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(user_id),
                        FOREIGN KEY (reviewer_id) REFERENCES users(user_id)
                      )''')
    
    conn.commit()
    conn.close()

# Function to add a new user
def add_user(name, email, password, profile_image=None, location=None):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute("INSERT INTO users (name, email, password, profile_image, location) VALUES (?, ?, ?, ?, ?)",
                   (name, email, hashed_password, profile_image, location))
    conn.commit()
    conn.close()

# Function to authenticate a user
def authenticate_user(email, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user[1], password):
        return user
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
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %I:%M %p')
    cursor.execute("INSERT INTO reviews (user_id, reviewer_id, rating, comment, timestamp) VALUES (?, ?, ?, ?, ?)",
                   (user_id, reviewer_id, rating, comment, timestamp))
    conn.commit()
    conn.close()

# Function to get reviews for a specific user or resource
def get_reviews(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT reviews.review_id, reviews.rating, reviews.comment, reviews.timestamp, users.name 
                      FROM reviews 
                      JOIN users ON reviews.reviewer_id = users.user_id 
                      WHERE reviews.user_id = ?''', (user_id,))
    reviews = cursor.fetchall()
    conn.close()
    return reviews