1. Project Overview
Hyrule Archives is a Progressive Web App (PWA) built for users to share and manage reviews of The Legend of Zelda series. This project was developed as part of the Year 12 Software Engineering Assessment (AT1), focusing on secure user authentication, relational database management, and Agile methodologies.


2. Key Features
User Authentication: Secure registration and login system with password hashing.

CRUD Functionality: Logged-in users can Create, Read, Update, and Delete their own reviews.

Relational Database: Stores user and review data using SQLite with linked table relationships.

Security: Built-in protection against SQL Injection and Cross-Site Scripting (XSS).

PWA Support: Installable on mobile and desktop devices with offline capabilities via Service Workers.


3. Technology Stack
Backend: Python 3.x, Flask Web Framework

Database: SQLite 3 with SQLAlchemy ORM

Security: Werkzeug (Password Hashing), Jinja2 (Auto-escaping)

Frontend: HTML5, CSS3, JavaScript (ES6)

Version Control: GitHub


4. Setup and Installation
Prerequisites
Ensure you have Python installed. You will also need pip to install dependencies.

Installation Steps
Clone the Repository:

Bash
git clone https://github.com/[Your-Username]/hyrule-archives-pwa.git
cd hyrule-archives-pwa
Install Dependencies:

Bash
pip install flask flask-sqlalchemy flask-login
Initialize the Database:
The database will automatically be created on the first run of the application.

Run the Application:

Bash
python app.py
Access the Site:
Open your browser and navigate to http://127.0.0.1:5000


5. Security Implementation
Hashing: Passwords are never stored in plain text; they are hashed using the pbkdf2:sha256 method (via Werkzeug).

XSS Protection: All user-generated content is sanitized through the Jinja2 templating engine.

SQL Injection: By using SQLAlchemy's Object-Relational Mapping (ORM), user inputs are treated as data, not executable code.