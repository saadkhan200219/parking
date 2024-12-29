from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a more secure secret key
CORS(app)  # Enable CORS for all routes

# MySQL connection setup with error handling
def get_db_connection():
    try:
        return mysql.connector.connect(
            host='localhost',
            user='root',
            password='karachi123',  # Change to your MySQL password
            database='car_parking_system'
        )
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Serve static files (CSS, JS, etc.) directly from the front-end folder
@app.route('/<path:filename>')
def serve_frontend_files(filename):
    # Serve files from the front-end folder
    front_end_path = os.path.join(app.root_path, '..', 'front-end')
    
    # Check if the requested file exists, and serve it
    if os.path.isfile(os.path.join(front_end_path, filename)):
        return send_from_directory(front_end_path, filename)
    
    # If the file is not found, fallback to serving index.html for SPA behavior
    return send_from_directory(front_end_path, 'index.html')

# Default route for the home page
@app.route('/')
def serve_index():
    return send_from_directory(os.path.join(app.root_path, '..', 'front-end'), 'index.html')


# API route for signup
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    if conn is None:
        return jsonify({'message': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, hashed_password))
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Error as e:
        conn.rollback()
        return jsonify({'message': f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()

# API route for login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'message': 'Database connection failed'}), 500

    cursor = conn.cursor()
    cursor.execute('SELECT id, password_hash FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if user and check_password_hash(user[1], password):
        session['user_id'] = user[0]  # Store user ID in session
        return jsonify({'message': 'Login successful', 'redirect_url': '/'}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# API route for logout
@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # Remove user from session
    return jsonify({'message': 'Logged out successfully'}), 200

# API route for adding a car
@app.route('/api/add_car', methods=['POST'])
def add_car():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401  # Check if user is logged in

    data = request.get_json()
    car_number = data.get('car_number')
    owner_name = data.get('owner_name')
    slot_number = data.get('slot_number')

    if not car_number or not owner_name or not slot_number:
        return jsonify({'message': 'Car number, owner name, and slot number are required'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'message': 'Database connection failed'}), 500

    cursor = conn.cursor()
    cursor.execute('SELECT is_occupied FROM slots WHERE slot_number = %s', (slot_number,))
    slot = cursor.fetchone()

    if not slot or slot[0] == 1:  # If slot is occupied or not found
        conn.close()
        return jsonify({'message': 'This slot is already taken or invalid slot number'}), 400

    # Add car entry only if the slot is valid and not occupied
    cursor.execute('INSERT INTO cars (car_number, owner_name, slot_number) VALUES (%s, %s, %s)',
                   (car_number, owner_name, slot_number))
    cursor.execute('UPDATE slots SET is_occupied = TRUE WHERE slot_number = %s', (slot_number,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Car added successfully'}), 201

# API route for viewing slots
@app.route('/api/view_slots', methods=['GET'])
def view_slots():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401  # Check if user is logged in

    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({'message': 'Database connection failed'}), 500

        cursor = conn.cursor()
        cursor.execute('SELECT slot_number, is_occupied FROM slots')
        slots = cursor.fetchall()
        conn.close()

        result = [{"slot_number": slot[0], "is_occupied": slot[1]} for slot in slots]
        return jsonify(result), 200
    except Error as e:
        return jsonify({'message': f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
