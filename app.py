from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import mysql.connector
import re
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import timedelta
from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from datetime import datetime, timedelta





app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True in production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Or 'Strict' based on your requirements
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=31
)  # Set a long session duration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'saadkhan200219@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'zvyc oxml gtjf vdvm'  # Your email password or app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'saadkhan200219@gmail.com'
mail = Mail(app)



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

def send_email(to_email, subject, body):
    msg = Message(subject, recipients=[to_email])
    msg.body = body
    try:
        print(f"Sending email to {to_email} with subject {subject}")  # Debugging line
        mail.send(msg)
        print("Email sent successfully.")  # Debugging line
    except Exception as e:
        print(f"Error sending email: {e}")


def generate_parking_code(length=6):
    """Generate a random alphanumeric parking code."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

# API route for signup
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Validate required fields
    if not username or not email or not password:
        return jsonify({"message": "Username, email, and password are required"}), 400

    # Validate email format
    email_regex = r'^\S+@\S+\.\S+$'
    if not re.match(email_regex, email):
        return jsonify({"message": "Invalid email format"}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Database connection failed"}), 500

    cursor = conn.cursor()
    try:
        # Insert user into the database
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, hashed_password),
        )
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        conn.rollback()
        # Check for duplicate email or username error
        if "Duplicate entry" in str(e):
            if "for key 'users.email'" in str(e):
                return jsonify({"message": "Email is already registered"}), 400
            elif "for key 'users.username'" in str(e):
                return jsonify({"message": "Username is already taken"}), 400
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()



@app.route("/api/remove-slot/<int:slot_id>", methods=["DELETE"])
def remove_slot(slot_id):
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    user_id = session["user_id"]  # Get the user_id from session

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Ensure the slot is occupied before trying to remove it
        cursor.execute("SELECT is_occupied FROM slots WHERE slot_number = %s", (slot_id,))
        slot = cursor.fetchone()

        if not slot or slot[0] == 0:  # If the slot is not occupied
            return jsonify({"message": "Slot is not occupied or does not exist"}), 400

        # Fetch the car details before deletion
        cursor.execute("SELECT car_number FROM cars WHERE slot_number = %s", (slot_id,))
        car = cursor.fetchone()

        if car:
            car_number = car[0]  # Get the car number
            print(f"Car found: {car_number}")  # Debugging line to check the car details

            # Get the user email before removing the car
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            
            if user:
                user_email = user[0]  # Get the email of the user
                print(f"Sending email to: {user_email}")  # Debugging line to check the user email
                
                # Send the email
                send_email(user_email, "Your car has been removed from the parking slot", 
                           f"Your car with number {car_number} has been removed from slot number {slot_id}. The slot is now available.")

            # Proceed with slot and car removal
            cursor.execute("UPDATE slots SET is_occupied = 0 WHERE slot_number = %s", (slot_id,))
            cursor.execute("DELETE FROM cars WHERE slot_number = %s", (slot_id,))  # Remove car entry

        else:
            print(f"No car found in slot {slot_id}")  # Debugging line if no car was found

        conn.commit()
        return jsonify({"message": "Slot removed successfully"}), 200

    except Exception as e:
        print(f"Error removing slot: {e}")
        return jsonify({"message": f"Error removing slot: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()



@app.route("/api/admin/remove-car", methods=["POST"])
def remove_car():
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    car_id = data.get("carId")
    slot_number = data.get("slotNumber")

    if not car_id or not slot_number:
        return jsonify({"message": "Car ID and Slot Number are required."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Database connection failed."}), 500

    cursor = conn.cursor()
    try:
        # Check if the car exists in the database
        cursor.execute("SELECT car_number FROM cars WHERE id = %s", (car_id,))
        car = cursor.fetchone()

        if not car:
            return jsonify({"message": "Car not found."}), 404

        car_number = car[0]

        # Check if the slot is occupied by this car
        cursor.execute("SELECT is_occupied FROM slots WHERE slot_number = %s", (slot_number,))
        slot = cursor.fetchone()

        if not slot or slot[0] == 0:
            return jsonify({"message": "The slot is not occupied."}), 400

        # Fetch admin email for sending notification
        cursor.execute("SELECT email FROM users WHERE id = %s", (session["user_id"],))
        admin = cursor.fetchone()

        if admin:
            admin_email = admin[0]
            send_email(
                admin_email,
                "Car Removal Notification",
                f"The car with number {car_number} has been removed from slot number {slot_number}."
            )

        # Remove the car from the cars table
        cursor.execute("DELETE FROM cars WHERE id = %s", (car_id,))

        # Update the slot to set is_occupied to 0
        cursor.execute("UPDATE slots SET is_occupied = 0 WHERE slot_number = %s", (slot_number,))

        conn.commit()
        return jsonify({"message": "Car removed and slot updated successfully."}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"message": f"Error: {str(e)}"}), 500

    finally:
        cursor.close()
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
                (SELECT COUNT(*) FROM slots) - (SELECT COUNT(*) FROM slots WHERE is_occupied = 1) AS available_slots,
                s.slot_number, c.car_number, c.from_date, c.to_date
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

        # Fetch the rows
        data = cursor.fetchall()
        print("Query Results:", data)

        # Check if any data was returned
        if not data:
            # If no cars or occupied slots, fetch the username
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user_info = cursor.fetchone()
            username = user_info['username'] if user_info else 'User'  # Default 'User' if not found
            cursor.execute("SELECT COUNT(*) FROM slots WHERE is_occupied = 0")  # Counting available slots
            available_slots_data = cursor.fetchone()
            available_slots = available_slots_data["COUNT(*)"] if available_slots_data else 0  # Default to 0 if no data

            return jsonify({
                "username": username,
                "total_cars": 0,
                "available_slots": available_slots,
                "occupied_slots": []
            })

        # If data exists, use the first record for username and return cars and slots
        response = {
            "username": data[0]["username"],  # The username is retrieved from the first row
            "total_cars": data[0]["total_cars"],
            "available_slots": data[0]["available_slots"],
            "occupied_slots": [
                {
                    "slot_number": row["slot_number"],
                    "car_number": row["car_number"],
                    "from_date": str(row["from_date"]),  # Convert timedelta to string
                    "to_date": str(row["to_date"]),  # Convert timedelta to string
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





from datetime import datetime, timedelta

from datetime import datetime, timedelta
@app.route("/api/admin/view-all-slots", methods=["GET"])
def view_all_slots():
    # Debug session data
    print("Session during view-all-slots request:", session)

    # Check if user is an admin
    if not session.get("is_admin"):
        return jsonify({"message": "Unauthorized access, admin privileges required"}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        cursor = conn.cursor()
        # Query to fetch data from cars table and corresponding username from users table
        cursor.execute("""
            SELECT cars.*, users.username
            FROM cars
            JOIN users ON cars.user_id = users.id
        """)
        cars_with_users = cursor.fetchall()

        # Convert datetime or timedelta objects to strings
        cars_list = []
        for record in cars_with_users:
            record_data = list(record)  # Convert tuple to list to modify the data
            for i, value in enumerate(record_data):
                if isinstance(value, datetime):
                    record_data[i] = value.isoformat()  # Convert datetime to string
                elif isinstance(value, timedelta):
                    record_data[i] = str(value)  # Convert timedelta to string
            cars_list.append(record_data)

        cursor.close()
        conn.close()

        return jsonify(cars_list), 200
    except Exception as e:
        return jsonify({"message": f"Error querying database: {str(e)}"}), 500






@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)  # Remove user from session
    return jsonify({"message": "Logged out successfully"}), 200

@app.route("/api/add_car", methods=["POST"])
def add_car():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"message": "User not logged in"}), 401

    data = request.get_json()
    car_number = data["car_number"]
    slot_number = data["slot_number"]
    from_date = data["from_date"]  # Get the from_date from the request (time format)
    to_date = data["to_date"]      # Get the to_date from the request (time format)
    total_charge = data["total_charge"]
    # Validate that all required fields are provided
    if not car_number or not slot_number or not from_date or not to_date:
        return jsonify({"message": "Missing required fields"}), 400

    # Validate time format (HH:MM:SS)
    # try:
    #     from datetime import datetime
    #     datetime.strptime(from_date, "%H:%M:%S")  # Ensure from_date is a valid time string
    #     datetime.strptime(to_date, "%H:%M:%S")    # Ensure to_date is a valid time string
    # except ValueError:
    #     return jsonify({"message": "Invalid time format. Please use HH:MM:SS."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Add the car to the database, including from_date, to_date, and section
        cursor.execute(
            """ 
            INSERT INTO cars (car_number, slot_number, user_id, from_date, to_date,total_charge )
            VALUES (%s, %s, %s, %s, %s, %s)
        """,
            (car_number, slot_number, user_id, from_date, to_date,total_charge),
        )

        # Update the slot status to occupied

        conn.commit()

        # Retrieve the user's email from the database
        cursor.execute(
            """ 
            SELECT email FROM users WHERE id = %s
        """,
            (user_id,),
        )
        user_email = cursor.fetchone()
        if not user_email:
            return jsonify({"message": "User email not found"}), 500

        user_email = user_email[0]  # Extract the email from the query result
        parking_code = generate_parking_code()

        # Send a confirmation email to the user
        subject = 'Parking Slot Booked'
        message = f'Your car with number {car_number} has been successfully booked for parking in slot number {slot_number} from {from_date} to {to_date} with total bill of {total_charge}. your parking code is {parking_code}'

        send_email(user_email, subject, message)

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
