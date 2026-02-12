
#  Secure REST API Gateway with JWT Authentication and Rate Limiting

##  Project Overview

This project presents the design and implementation of a secure REST API Gateway developed using Flask. The system enhances API security by integrating JWT-based authentication and rate limiting mechanisms to prevent unauthorized access, brute-force attempts, and API abuse.

The application follows a modular and lightweight architecture where authentication, authorization, and request control operate as structured components within the API gateway.

---

##  Objectives

* Implement stateless authentication using JSON Web Tokens (JWT)
* Protect sensitive API endpoints
* Enforce token validation and expiration handling
* Prevent excessive API usage using rate limiting
* Demonstrate practical API security implementation

---

##  System Architecture

1. Client sends login request to `/login`
2. Server validates credentials
3. JWT token is generated using HS256 algorithm
4. Token is returned to the client
5. Client includes token in Authorization header (Bearer Token)
6. Protected endpoints validate token before granting access
7. Rate limiting restricts excessive requests per IP address

---

##  Technologies Used

* **Python 3**
* **Flask** – Web framework
* **PyJWT** – Token generation and validation
* **Flask-Limiter** – Rate limiting implementation
* **Postman** – API testing and validation

---

##  Key Features

### 1️ JWT-Based Authentication

* Secure login endpoint
* Token generation with payload (username + expiration)
* HS256 cryptographic signing
* Stateless authentication model

### 2️ Token Validation Middleware

* Custom `token_required` decorator
* Checks:

  * Missing token
  * Expired token
  * Invalid signature
* Returns appropriate 401 responses

### 3️ Rate Limiting Protection

* 5 requests per minute per IP
* Returns HTTP 429 (Too Many Requests)
* Prevents brute-force and DoS attempts

### 4️ Secure Endpoint Protection

* `/data` route protected with:

  * JWT validation
  * Rate limiting control

---

##  API Endpoints

| Method | Endpoint | Description                            |
| ------ | -------- | -------------------------------------- |
| POST   | `/login` | Authenticates user and generates JWT   |
| GET    | `/data`  | Protected endpoint requiring valid JWT |

---

##  How to Run the Project

### Step 1: Clone Repository

```
git clone <repository-url>
cd <project-folder>
```

### Step 2: Create Virtual Environment (Recommended)

```
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```
pip install -r requirements.txt
```

### Step 4: Run Application

```
python app.py
```

Server will start at:

```
http://127.0.0.1:5000
```

---

##  Testing

The API was tested using **Postman**:

* Successful login returns JWT token
* Unauthorized access returns 401
* Tampered token returns 401
* Exceeding rate limit returns 429

---

##  Security Implementation Highlights

* Stateless authentication (No server-side session storage)
* Cryptographic token signing
* Expiration-based access control
* Middleware-based access enforcement
* IP-based request throttling

---

##  Future Enhancements

* Role-Based Access Control (RBAC)
* Refresh token mechanism
* Logging and monitoring dashboard
* Database-backed user authentication
* Production deployment using WSGI server

---


**Rachita**
