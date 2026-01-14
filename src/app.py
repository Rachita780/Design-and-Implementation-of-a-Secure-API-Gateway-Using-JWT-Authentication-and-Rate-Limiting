from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

# Rate limiting imports
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Secret key for JWT
SECRET_KEY = "mysecretkey"

# Initialize rate limiter (per IP)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

# ---------------- TOKEN VERIFICATION ----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check Authorization header
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split(" ")
            if len(parts) == 2:
                token = parts[1]

        if not token:
            return jsonify({'message': 'Token missing'}), 401

        try:
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated


# ---------------- LOGIN API ----------------
@app.route('/login', methods=['POST'])
def login():
    data = request.json

    if not data:
        return jsonify({'message': 'No data received'}), 400

    username = data.get('username')
    password = data.get('password')

    # Dummy credentials for demo
    if username == "admin" and password == "admin123":
        token = jwt.encode(
            {
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            },
            SECRET_KEY,
            algorithm='HS256'
        )

        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401


# ---------------- PROTECTED API (RATE LIMITED) ----------------
@app.route('/data', methods=['GET'])
@limiter.limit("5 per minute")
@token_required
def get_data():
    return jsonify({'message': 'Secure data accessed'})


# ---------------- START SERVER ----------------
if __name__ == '__main__':
    app.run(debug=True)
