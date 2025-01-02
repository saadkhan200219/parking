from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import timedelta



app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True in production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Or 'Strict' based on your requirements
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=31
)  # Set a long session duration

app.secret_key = "your_secret_key_here"  # Change this to a more secure secret key
CORS(app, supports_credentials=True)


# MySQL connection setup with error handling
def get_db_connection():
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="karachi123",  # Change to your MySQL password
            database="car_parking_system",
        )
    except Exception as e:
        print(f"Error connecting to MySQL: {e}")
        return None


# Serve static files (CSS, JS, etc.) directly from the front-end folder
@app.route("/<path:filename>")
def serve_frontend_files(filename):
    # Serve files from the front-end folder
    front_end_path = os.path.join(app.root_path, "..", "front-end")

    # Check if the requested file exists, and serve it
    if os.path.isfile(os.path.join(front_end_path, filename)):
        return send_from_directory(front_end_path, filename)

    # If the file is not found, fallback to serving index.html for SPA behavior
    return send_from_directory(front_end_path, "index.html")


# Default route for the home page
@app.route("/")
def serve_index():
    return send_from_directory(
        os.path.join(app.root_path, "..", "front-end"), "index.html"
    )


# API route for signup
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Database connection failed"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, hashed_password),
        )
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()


# API route for login
# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({'message': 'Username and password are required'}), 400

#     conn = get_db_connection()
#     if conn is None:
#         return jsonify({'message': 'Database connection failed'}), 500

#     cursor = conn.cursor()
#     cursor.execute('SELECT id, password_hash FROM users WHERE username = %s', (username,))
#     user = cursor.fetchone()

#     if user and check_password_hash(user[1], password):
#         session['user_id'] = user[0]  # Store user ID in session
#         return jsonify({'message': 'Login successful', 'redirect_url': '/'}), 200
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401


# #from flask import Flask, request, jsonify, session
# from werkzeug.security import check_password_hash
# import psycopg2  # Assuming you're using psycopg2 for PostgreSQL (or adjust accordingly)

# app = Flask(__name__)

# # Secret key for session signing
# app.secret_key = 'your_secret_key'

# def get_db_connection():
#     try:
#         conn = psycopg2.connect(
#             dbname='your_db', user='your_user', password='your_password', host='localhost'
#         )
#         return conn
#     except Exception as e:
#         return None

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    print("Before login - session: ", session)  # Print session before login

    if not data:
        return jsonify({"message": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password_hash, is_admin FROM users WHERE username = %s", (username,)
        )
        user = cursor.fetchone()

        if user and check_password_hash(user[1], password):
            session.permanent = True
            session["user_id"] = user[0]  # Store user ID in session
            session["is_admin"] = user[2]  # Store admin status in session
            print("After login - session: ", session)  # Print session after login
            cursor.close()
            conn.close()

            # Redirect based on admin status
            if user[2]:  # If the user is an admin
                return jsonify({"message": "Login successful", "redirect_url": "/admin-slots.html"}), 200
            else:  # Regular user
                return jsonify({"message": "Login successful", "redirect_url": "/index.html"}), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid credentials"}), 401
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({"message": f"Error querying database: {str(e)}"}), 500


# API route for fetching dashboard data
@app.route("/api/dashboard_data", methods=["GET"])
def dashboard_data():
    # Check if the user is logged in
    print("Session data: ", session)
    user_id = session.get("user_id")
    print("Logged-in User ID:", user_id)

    if not user_id:
        return jsonify({"message": "User not logged in"}), 401

    try:
        # Get a database connection
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Query to get the total cars, available slots, and occupied slots for the logged-in user
        cursor.execute(
            """
            SELECT 
                u.username,
                u.id AS user_id,
                (SELECT COUNT(*) FROM cars WHERE user_id = %s) AS total_cars,
                (SELECT COUNT(*) FROM slots WHERE is_occupied = 0) AS available_slots,
                s.slot_number, c.car_number, c.created_at
            FROM 
                users u
            LEFT JOIN 
                cars c ON u.id = c.user_id
            LEFT JOIN 
                slots s ON c.slot_number = s.slot_number
            WHERE 
                u.id = %s AND s.is_occupied = 1
            """,
            (user_id, user_id),
        )

        # Fetch all the rows
        data = cursor.fetchall()
        print("Query Results:", data)

        # Return a default response if no data is found
        if not data:
            return jsonify({
                "username": "Guest",
                "total_cars": 0,
                "available_slots": 0,
                "occupied_slots": []
            })

        # Create the response object
        response = {
            "username": data[0]["username"],
            "total_cars": data[0]["total_cars"],
            "available_slots": data[0]["available_slots"],
            "occupied_slots": [
                {
                    "slot_number": row["slot_number"],
                    "car_number": row["car_number"],
                    "created_at": row["created_at"],
                }
                for row in data
            ],
        }

        # Return the JSON response
        return jsonify(response)

    except Exception as e:
        print(f"Error fetching dashboard data: {e}")
        return jsonify({"message": "Error fetching dashboard data"}), 500

# API route for logout

@app.route("/api/admin/view-all-slots", methods=["GET"])
def view_all_slots():
    # Check if the user is logged in and is an admin
    if "user_id" not in session or not session.get("is_admin"):
        return jsonify({"message": "Unauthorized"}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        
        # Query to fetch all users and their slots
        cursor.execute("""
    SELECT
        users.username,
        slots.slot_number,
        slots.is_occupied
    FROM
        users
    LEFT JOIN
        cars ON users.id = cars.user_id  -- Corrected to join by user_id
    LEFT JOIN
        slots ON cars.slot_number = slots.slot_number
    ORDER BY
        slots.slot_number
""")

        result = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify({"message": "Slots retrieved successfully", "slots": result}), 200

    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({"message": f"Error retrieving slots: {str(e)}"}), 500











@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)  # Remove user from session
    return jsonify({"message": "Logged out successfully"}), 200


# API route for adding a car
@app.route("/api/add_car", methods=["POST"])
def add_car():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"message": "User not logged in"}), 401

    data = request.get_json()
    car_number = data["car_number"]
    slot_number = data["slot_number"]

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """ 
            INSERT INTO cars (car_number, slot_number, user_id)
            VALUES (%s, %s, %s)
        """,
            (car_number, slot_number, user_id),
        )

        cursor.execute(
            """ 
            UPDATE slots SET is_occupied = 1 WHERE slot_number = %s
        """,
            (slot_number,),
        )

        conn.commit()
        return jsonify({"message": "Car added successfully"}), 201

    except Exception as e:
        print(f"Error adding car: {e}")
        return jsonify({"message": "Error adding car"}), 500


# API route for viewing slots
@app.route("/api/view_slots", methods=["GET"])
def view_slots():
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT slot_number, is_occupied FROM slots")
        slots = cursor.fetchall()

        result = [{"slot_number": slot[0], "is_occupied": slot[1]} for slot in slots]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True)
