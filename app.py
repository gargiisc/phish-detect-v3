from flask import Flask, jsonify, request, render_template, redirect, url_for, session
import numpy as np
import sqlite3
import pickle
import warnings
from convert import convertion
from feature import FeatureExtraction
import pyrebase
from dotenv import load_dotenv
import os
warnings.filterwarnings('ignore')

# Initialize Flask app
load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Load the phishing detection model
with open("gbc.pkl", "rb") as file:
    gbc = pickle.load(file)

# Firebase configuration
firebaseConfig = {
    "apiKey": "AIzaSyCbS0fWLY65cJlzUKCcpJH2uNddhBho1rM",
    "authDomain": "phish-detect.firebaseapp.com",
    "projectId": "phish-detect",
    "storageBucket": "phish-detect.firebasestorage.app",
    "messagingSenderId": "1031544679518",
    "appId": "1:1031544679518:web:8efe83d91c6724396cd8cf",
    "measurementId": "G-7FB1SMPKKD",
    "databaseURL": "https://phish-detect-default-rtdb.firebaseio.com/"
}

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()

# Database setup
def init_db():
    conn = sqlite3.connect("phishing_urls.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phishing_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Routes
@app.route("/")
def home():
    phishing_url = request.args.get("phishing_url")
    user = session.get("user")
    conn = sqlite3.connect("phishing_urls.db")
    cursor = conn.cursor()
    cursor.execute("SELECT url, detected_at FROM phishing_urls ORDER BY detected_at DESC")
    urls = cursor.fetchall()
    conn.close()
    return render_template("index.html", phishing_url=phishing_url, user=user, urls=urls)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            session["user"] = auth.get_account_info(user['idToken'])["users"][0]
            return redirect(url_for("home"))
        except:
            return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html")

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match.")

        try:
            user = auth.create_user_with_email_and_password(email, password)
            session["user"] = auth.get_account_info(user['idToken'])["users"][0]
            return redirect(url_for("home"))
        except:
            return render_template("signup.html", error="Error creating account. Try again.")
    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        print("URL:", url)  
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        print("Extracted Features:", x) 
        y_pred = gbc.predict(x)[0]
        y_proba = gbc.predict_proba(x)
        print("Prediction:", y_pred) 
        print("Probabilities (Safe, Malicious):", y_proba) 

        y_pro_phishing = y_proba[0, 0]
        y_pro_non_phishing = y_proba[0, 1]

        threshold = 0.5  
        if y_pro_non_phishing > threshold:
            y_pred = 1  # Safe
        else:
            y_pred = -1  # Malicious

        if y_pred == 1:
            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing * 100)
            xx = y_pro_non_phishing
            name = convertion(url, int(y_pred))
            conn = sqlite3.connect("phishing_urls.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO phishing_urls (url) VALUES (?)", (url,))
            conn.commit()
            conn.close()
        else:
            xx = y_pro_phishing
            name = convertion(url, int(y_pred))
        prediction_text = "Safe" if y_pred == 1 else "Malicious"
        return render_template(
            "index.html",
            name=name, 
            xx=xx,
            url=url,
            prediction_text=prediction_text,
            y_pro_phishing=y_pro_phishing,
            y_pro_non_phishing=y_pro_non_phishing,
            user=session.get("user")
        )
@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    obj = FeatureExtraction(url)
    x = np.array(obj.getFeaturesList()).reshape(1, 30)
    y_pred = gbc.predict(x)[0]

    # Save phishing URL to the database if detected
    if y_pred == -1:
        conn = sqlite3.connect("phishing_urls.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO phishing_urls (url) VALUES (?)", (url,))
        conn.commit()
        conn.close()

    return jsonify({"phishing": bool(y_pred == -1)})

@app.route('/phishing_urls')
def phishing_urls():
    conn = sqlite3.connect("phishing_urls.db")
    cursor = conn.cursor()
    cursor.execute("SELECT url, detected_at FROM phishing_urls ORDER BY detected_at DESC")
    urls = cursor.fetchall()
    conn.close()
    user = session.get("user")
    return render_template("phishing_urls.html", urls=urls)

if __name__ == "__main__":
    app.run(debug=True)