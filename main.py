# Import necessary modules and classes
import sqlite3
import os
import hashlib
import re
from flask import Flask, jsonify, render_template, request, g, session, url_for, redirect, make_response
import logging

logging.basicConfig(level=logging.DEBUG)

firewall_enabled = True

# Create a Flask app
app = Flask(__name__)
app.database = "sample.db"
app.secret_key = "100563fa9182b2b67948c942b549a2775109893221e8a4a3"  # Change this to a random secret key

# Import functions from firewall_security.py
from firewall_security import security_scan, check_default_credentials

@app.route('/api/v1.0/updateFirewallStatus', methods=['POST'])
def update_firewall_status():
    global firewall_enabled
    if request.method == 'POST':
        enabled = request.json.get('enabled', False)
        firewall_enabled = enabled

        # You can perform any required logic to update the firewall status here
        # For now, let's print the status to the console
        print('Firewall Status Updated:', enabled)

        # Return a response if needed
        return jsonify({'status': 'success', 'message': 'Firewall status updated'})

    return jsonify({'status': 'fail', 'message': 'Invalid request'}), 400

# Define the home route
@app.route('/')
def home():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # Perform security scan based on firewall status
        if firewall_enabled:
            if not security_scan(""):
                return jsonify({'status': 'fail', 'message': 'Sorry, You have been blocked. Please Try Again..'})
        else:
            return jsonify({'status': 'fail', 'message': 'You are not allowed to perform this task without enabling the firewall.'})
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

# Define the login route
@app.route('/login')
def login():
    # Check if the user is already logged in
    if 'logged_in' in session and session['logged_in']:
        # Perform security scan based on firewall status
        if firewall_enabled:
            if not security_scan():
                return jsonify({'status': 'fail', 'message': 'Sorry, You have been blocked. Please Try Again..'})
        else:
            return jsonify({'status': 'fail', 'message': 'You are not allowed to perform this task without enabling the firewall.'})
        return redirect(url_for('home'))

    # If not logged in, render the login page without the navbar
    return render_template('login.html', show_navbar=False)

# Define the restock route with GET and POST methods
@app.route('/restock', methods=['GET', 'POST'])
def restock():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # If it's a POST request, handle restocking logic
        if request.method == 'POST':
            # Perform security scan based on firewall status
            if firewall_enabled:
                if not security_scan():
                    return jsonify({'status': 'fail', 'message': 'Sorry, You have been blocked. Please Try Again..'})

            g.db = connect_db()
            name, quan, price = (request.json['name'], request.json['quantity'], request.json['price'])

            curs = g.db.execute("""INSERT INTO shop_items(name, quantity, price) VALUES(?,?,?)""", (name, quan, price))
            g.db.commit()
            g.db.close()
            return jsonify({'status': 'OK', 'name': name, 'quantity': quan, 'price': price})

        # If it's a GET request, render the restock page
        return render_template('restock.html')

    # If not logged in, redirect to the login page
    return redirect(url_for('login'))

# Define the logout route
@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    return redirect(url_for('login'))

# Define the API route for login with POST method
@app.route('/api/v1.0/storeLoginAPI/', methods=['POST'])
def loginAPI():
    if request.method == 'POST':
        uname, pword = (request.json['username'], request.json['password'])
        g.db = connect_db()

        # Perform security check based on firewall status
        if firewall_enabled:
            security_scan_uname = security_scan(uname, request.json) if firewall_enabled else True
            security_scan_pword = security_scan(pword, request.json) if firewall_enabled else True

            if not security_scan_uname or not security_scan_pword:
                g.db.close()
                return jsonify({'status': 'fail', 'message': 'Sorry, You have been blocked. Please Try Again..'})
        else:
            # If the firewall is disabled, skip the security scan
            g.db.close()
            return jsonify({'status': 'fail', 'message': 'Firewall is disabled. You are not allowed to login.'})

        # Check if the credentials are valid using the provided function
        if check_default_credentials(uname, pword):
            # Set the session to mark the user as logged in
            session['logged_in'] = True
            g.db.close()

            # Print statement to debug (remove this in production)
            print("Redirecting to home.html")

            # Create a JSON response with a client-side redirect
            response = make_response(jsonify({'status': 'success', 'message': 'Login successful', 'redirect': '/'}))
            response.headers['Content-Type'] = 'application/json'

            return response

        else:
            g.db.close()
            return jsonify({'status': 'fail', 'message': 'Invalid credentials'})

# Define the API route for adding items
@app.route('/api/v1.0/storeAPI', methods=['POST'])
def add_item_api():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # Perform security scan based on firewall status
        if firewall_enabled:
            if not security_scan():
                return jsonify({'status': 'fail', 'message': 'Sorry, You have been blocked. Please Try Again..'})
        else:
            return jsonify({'status': 'fail', 'message': 'You are not allowed to perform this task without enabling the firewall.'})

        g.db = connect_db()
        try:
            name, quan, price = (request.json['name'], request.json['quantity'], request.json['price'])
            curs = g.db.execute("""INSERT INTO shop_items(name, quantity, price) VALUES(?,?,?)""", (name, quan, price))
            g.db.commit()
            g.db.close()
            return jsonify({'status': 'OK', 'name': name, 'quantity': quan, 'price': price, 'message': 'Item added successfully'})
        except Exception as e:
            g.db.close()
            return jsonify({'status': 'fail', 'message': f'Error adding item: {e}'}), 500

    # If not logged in, return an error
    return jsonify({'error': 'Access denied. Not logged in.', 'message': 'Redirecting to login page'}), 403

# Define the API route for searching items
@app.route('/api/v1.0/storeAPI', methods=['GET', 'POST'])
def searchAPI():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        search_item = request.args.get('item', '')

        # Perform security scan based on firewall status
        if firewall_enabled:
            if not security_scan(search_item):
                return jsonify({'status': 'fail', 'message': 'Sorry, You have been blocked. Please Try Again..'})
        else:
            return jsonify({'status': 'fail', 'message': '<bSearch Failed:</b> You are not allowed to perform this task without enabling the firewall.'})

        g.db = connect_db()

        if search_item:
            # If there's a specific item, search for it
            curs = g.db.execute("SELECT * FROM shop_items WHERE name=?", (search_item,))
            results = [{'name': row[0], 'quantity': row[1], 'price': row[2]} for row in curs.fetchall()]
        else:
            # If no specific item, retrieve all items
            curs = g.db.execute("SELECT * FROM shop_items")
            results = [{'name': row[0], 'quantity': row[1], 'price': row[2]} for row in curs.fetchall()]

        g.db.close()
        return jsonify(results)

    # If not logged in, return an error
    return jsonify({'error': 'Access denied. Not logged in.'}), 403

# Create password hashes
def hash_pass(passw):
    m = hashlib.md5()
    m.update(passw.encode('utf-8'))
    return m.hexdigest()

# Define the function to connect to the database
def connect_db():
    return sqlite3.connect(app.database)

if not os.path.exists(app.database):
    with sqlite3.connect(app.database) as connection:
        c = connection.cursor()

        # Create the shop_items table
        c.execute("""DROP TABLE IF EXISTS shop_items""")
        c.execute("""CREATE TABLE shop_items(name TEXT, quantity INTEGER, price TEXT)""")

        # Create the employees table
        c.execute("""CREATE TABLE employees(username TEXT, password TEXT)""")

        # Insert sample data into the shop_items table
        c.execute('INSERT INTO shop_items VALUES("water", 40, "100")')
        c.execute('INSERT INTO shop_items VALUES("juice", 40, "110")')
        c.execute('INSERT INTO shop_items VALUES("candy", 100, "10")')

        # Insert sample data into the employees table
        c.execute('INSERT INTO employees VALUES("itsjasonh", "{}")'.format(hash_pass("badword")))
        c.execute('INSERT INTO employees VALUES("theeguy9", "{}")'.format(hash_pass("badpassword")))
        c.execute('INSERT INTO employees VALUES("newguy29", "{}")'.format(hash_pass("pass123")))

        connection.commit()

# Rest of your Flask app code...

# Run the app if this is the main module
if __name__ == "__main__":
    app.run(host='0.0.0.0')
