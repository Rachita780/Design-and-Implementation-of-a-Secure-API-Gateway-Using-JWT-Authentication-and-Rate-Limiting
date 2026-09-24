from flask import Flask, request, jsonify, g, render_template
import jwt
import datetime
import os
import uuid

from functools import wraps
from dotenv import load_dotenv

from werkzeug.security import check_password_hash

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import create_tables, get_connection


# -------------------------------------------------
# APPLICATION SETUP
# -------------------------------------------------

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing from .env")


create_tables()


# -------------------------------------------------
# RATE LIMITER
# -------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
    headers_enabled=True
)


# -------------------------------------------------
# SECURITY LOGGING
# -------------------------------------------------

def log_event(event_type, username=None, details=None):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO security_logs
        (timestamp, username, event_type, ip_address, endpoint, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            username,
            event_type,
            request.remote_addr,
            request.path,
            details
        )
    )

    conn.commit()
    conn.close()


# -------------------------------------------------
# TOKEN CREATION
# -------------------------------------------------

def create_tokens(username, role):

    session_id = str(uuid.uuid4())

    now = datetime.datetime.now(datetime.timezone.utc)

    access_token = jwt.encode(
        {
            "user": username,
            "role": role,
            "type": "access",
            "sid": session_id,
            "iat": now,
            "exp": now + datetime.timedelta(minutes=30)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    refresh_token = jwt.encode(
        {
            "user": username,
            "role": role,
            "type": "refresh",
            "sid": session_id,
            "iat": now,
            "exp": now + datetime.timedelta(days=7)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return access_token, refresh_token


# -------------------------------------------------
# TOKEN REVOCATION CHECK
# -------------------------------------------------

def session_is_revoked(session_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM revoked_sessions
        WHERE session_id = ?
        """,
        (session_id,)
    )

    result = cursor.fetchone()

    conn.close()

    return result is not None


# -------------------------------------------------
# GET BEARER TOKEN
# -------------------------------------------------

def get_bearer_token():

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    parts = auth_header.split()

    if len(parts) != 2:
        return None

    if parts[0].lower() != "bearer":
        return None

    return parts[1]


# -------------------------------------------------
# ACCESS TOKEN REQUIRED
# -------------------------------------------------

def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        token = get_bearer_token()

        if not token:

            log_event(
                "TOKEN_MISSING",
                details="Authorization token was not supplied"
            )

            return jsonify({
                "message": "Token missing"
            }), 401

        try:

            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"]
            )

            if payload.get("type") != "access":

                log_event(
                    "INVALID_TOKEN_TYPE",
                    payload.get("user"),
                    "Access token required"
                )

                return jsonify({
                    "message": "Access token required"
                }), 401

            if session_is_revoked(payload.get("sid")):

                log_event(
                    "REVOKED_TOKEN",
                    payload.get("user")
                )

                return jsonify({
                    "message": "Token revoked"
                }), 401

            g.current_user = payload.get("user")
            g.current_role = payload.get("role")
            g.session_id = payload.get("sid")

        except jwt.ExpiredSignatureError:

            log_event(
                "TOKEN_EXPIRED"
            )

            return jsonify({
                "message": "Token expired"
            }), 401

        except jwt.InvalidTokenError:

            log_event(
                "INVALID_TOKEN"
            )

            return jsonify({
                "message": "Invalid token"
            }), 401

        return f(*args, **kwargs)

    return decorated


# -------------------------------------------------
# ADMIN ROLE REQUIRED
# -------------------------------------------------

def admin_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if g.current_role != "admin":

            log_event(
                "ACCESS_DENIED",
                g.current_user,
                "Admin role required"
            )

            return jsonify({
                "message": "Admin access required"
            }), 403

        return f(*args, **kwargs)

    return decorated


# -------------------------------------------------
# HOME
# -------------------------------------------------

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "message": "Secure API Gateway is running"
    }), 200


# -------------------------------------------------
# LOGIN
# -------------------------------------------------

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():

    data = request.get_json(silent=True)

    if not data:

        return jsonify({
            "message": "JSON data required"
        }), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:

        return jsonify({
            "message": "Username and password required"
        }), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    conn.close()

    if not user:

        log_event(
            "LOGIN_FAILED",
            username,
            "User does not exist"
        )

        return jsonify({
            "message": "Invalid credentials"
        }), 401

    if user["active"] != 1:

        log_event(
            "LOGIN_FAILED",
            username,
            "Account disabled"
        )

        return jsonify({
            "message": "Account disabled"
        }), 403

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        log_event(
            "LOGIN_FAILED",
            username,
            "Incorrect password"
        )

        return jsonify({
            "message": "Invalid credentials"
        }), 401

    access_token, refresh_token = create_tokens(
        user["username"],
        user["role"]
    )

    log_event(
        "LOGIN_SUCCESS",
        username
    )

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "role": user["role"]
    }), 200


# -------------------------------------------------
# NORMAL PROTECTED DATA
# -------------------------------------------------

@app.route("/data", methods=["GET"])
@limiter.limit("5 per minute")
@token_required
def get_data():

    log_event(
        "DATA_ACCESSED",
        g.current_user
    )

    return jsonify({
        "message": "Secure data accessed",
        "user": g.current_user,
        "role": g.current_role
    }), 200


# -------------------------------------------------
# ADMIN-ONLY ENDPOINT
# -------------------------------------------------

@app.route("/admin", methods=["GET"])
@limiter.limit("5 per minute")
@token_required
@admin_required
def admin():

    log_event(
        "ADMIN_ACCESS",
        g.current_user
    )

    return jsonify({
        "message": "Admin data accessed",
        "user": g.current_user
    }), 200


# -------------------------------------------------
# REFRESH JWT
# -------------------------------------------------

@app.route("/refresh", methods=["POST"])
def refresh():

    token = get_bearer_token()

    if not token:

        return jsonify({
            "message": "Refresh token missing"
        }), 401

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        if payload.get("type") != "refresh":

            return jsonify({
                "message": "Refresh token required"
            }), 401

        if session_is_revoked(payload.get("sid")):

            return jsonify({
                "message": "Session revoked"
            }), 401

        now = datetime.datetime.now(
            datetime.timezone.utc
        )

        new_access_token = jwt.encode(
            {
                "user": payload.get("user"),
                "role": payload.get("role"),
                "type": "access",
                "sid": payload.get("sid"),
                "iat": now,
                "exp": now + datetime.timedelta(minutes=30)
            },
            SECRET_KEY,
            algorithm="HS256"
        )

        log_event(
            "TOKEN_REFRESHED",
            payload.get("user")
        )

        return jsonify({
            "access_token": new_access_token
        }), 200

    except jwt.ExpiredSignatureError:

        return jsonify({
            "message": "Refresh token expired"
        }), 401

    except jwt.InvalidTokenError:

        return jsonify({
            "message": "Invalid refresh token"
        }), 401


# -------------------------------------------------
# LOGOUT / REVOKE SESSION
# -------------------------------------------------

@app.route("/logout", methods=["POST"])
@token_required
def logout():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO revoked_sessions
            (session_id, revoked_at)
            VALUES (?, ?)
            """,
            (
                g.session_id,
                datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()
            )
        )

        conn.commit()

    except Exception:

        pass

    finally:

        conn.close()

    log_event(
        "LOGOUT",
        g.current_user
    )

    return jsonify({
        "message": "Logged out successfully"
    }), 200


# -------------------------------------------------
# VIEW SECURITY LOGS - ADMIN ONLY
# -------------------------------------------------

@app.route("/logs", methods=["GET"])
@token_required
@admin_required
def view_logs():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM security_logs
        ORDER BY id DESC
        LIMIT 50
        """
    )

    logs = cursor.fetchall()

    conn.close()

    result = []

    for log in logs:

        result.append({
            "id": log["id"],
            "timestamp": log["timestamp"],
            "username": log["username"],
            "event_type": log["event_type"],
            "ip_address": log["ip_address"],
            "endpoint": log["endpoint"],
            "details": log["details"]
        })

    return jsonify(result), 200


# -------------------------------------------------
# RATE LIMIT ERROR
# -------------------------------------------------

@app.errorhandler(429)
def rate_limit_error(error):

    log_event(
        "RATE_LIMIT_EXCEEDED",
        details=str(error.description)
    )

    return jsonify({
        "message": "Too many requests",
        "details": str(error.description)
    }), 429

# -------------------------------------------------
# TEST RESULT RECORDING
# -------------------------------------------------

@app.route("/test-result", methods=["POST"])
def record_test_result():

    data = request.get_json()

    if not data or "test_name" not in data or "actual_status" not in data:
        return jsonify({
            "message": "test_name and actual_status are required"
        }), 400

    test_name = data["test_name"]
    actual_status = data["actual_status"]

    conn = get_connection()

    test = conn.execute(
        """
        SELECT expected_status
        FROM test_results
        WHERE test_name = ?
        """,
        (test_name,)
    ).fetchone()

    if test is None:
        conn.close()

        return jsonify({
            "message": "Unknown test name"
        }), 404

    expected_status = test["expected_status"]

    if actual_status == expected_status:
        result = "PASS"
    else:
        result = "FAIL"

    conn.execute(
        """
        UPDATE test_results
        SET actual_status = ?,
            result = ?,
            tested_at = ?
        WHERE test_name = ?
        """,
        (
            actual_status,
            result,
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            test_name
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "test_name": test_name,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "result": result
    }), 200

# -------------------------------------------------
# SECURITY VALIDATION DASHBOARD
# -------------------------------------------------

@app.route("/dashboard")
def dashboard():

    conn = get_connection()

    tests = conn.execute("""
        SELECT id, test_name, security_control,
               expected_status, actual_status,
               result, tested_at
        FROM test_results
        ORDER BY id
    """).fetchall()

    logs = conn.execute("""
        SELECT timestamp, username, event_type,
               ip_address, endpoint
        FROM security_logs
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    total_tests = len(tests)

    passed_tests = sum(
        1 for test in tests
        if test["result"] == "PASS"
    )

    failed_tests = sum(
        1 for test in tests
        if test["result"] == "FAIL"
    )

    not_run_tests = sum(
        1 for test in tests
        if test["result"] == "NOT RUN"
    )

    if total_tests > 0 and passed_tests == total_tests:
        overall_status = "All Tests Passed"
    elif failed_tests > 0:
        overall_status = "Attention Required"
    else:
        overall_status = "Testing In Progress"

    conn.close()

    return render_template(
        "dashboard.html",
        tests=tests,
        logs=logs,
        total_tests=total_tests,
        passed_tests=passed_tests,
        failed_tests=failed_tests,
        not_run_tests=not_run_tests,
        overall_status=overall_status
    )

# -------------------------------------------------
# RUN APPLICATION
# -------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
