# Secure API Gateway Using JWT Authentication and Rate Limiting

## Project Overview

This project presents the design and implementation of a **Secure REST API Gateway** developed using Python and Flask. The system provides a layered API security mechanism by integrating **JWT-based authentication, Role-Based Access Control (RBAC), access and refresh tokens, session revocation, IP-based rate limiting, security event logging, and a web-based security monitoring dashboard**.

The API Gateway acts as an intermediate security layer between the client and protected API resources. Incoming requests are validated before access is granted, helping prevent unauthorized access, excessive API requests, and misuse of authenticated sessions.

The project is implemented and tested locally using **Kali Linux, Flask, SQLite, Flask-Limiter, PyJWT, and Postman**.

---

## Objectives

* Develop a Flask-based REST API Gateway for protecting API endpoints.
* Implement database-backed user authentication using JWT access and refresh tokens.
* Implement Role-Based Access Control (RBAC) for Admin and User roles.
* Provide token validation, token refresh, logout, and session revocation mechanisms.
* Apply IP-based rate limiting to control excessive API requests.
* Record important security events using an SQLite database.
* Validate the implemented security mechanisms using Postman.
* Provide a web-based dashboard for displaying security validation results and recent security events.

---

## System Architecture

The system follows a layered architecture consisting of:

### 1. Presentation Layer

The presentation layer includes:

* **Postman** for sending and testing HTTP requests.
* **Security Monitoring Dashboard** for displaying validation results and recent security events.

### 2. Application and Security Layer

The application and security layer is implemented using **Python and Flask** and acts as the API Gateway.

It provides:

* User authentication
* JWT generation and validation
* Access and refresh token management
* Role-Based Access Control (RBAC)
* Logout and session revocation
* IP-based rate limiting
* Security event logging
* Protected API resource access

### 3. Data Layer

The system uses an **SQLite database (`gateway.db`)** for persistent storage of:

* User information
* User roles
* Revoked sessions
* Security events
* Security validation test results

---

## Request Flow

1. The client sends login credentials to the `/login` endpoint.
2. The Flask API Gateway validates the credentials against the SQLite database.
3. After successful authentication, JWT access and refresh tokens are generated.
4. The client sends the access token with requests to protected endpoints.
5. The gateway validates the JWT before processing the request.
6. RBAC verifies whether the authenticated user has permission to access restricted resources.
7. Rate limiting controls the number of requests received from an IP address.
8. Security-related activities are recorded in the SQLite database.
9. Logout invalidates the associated session and prevents reuse of revoked credentials.
10. Security validation results and recent events are displayed through the monitoring dashboard.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Core programming language |
| Flask | REST API and API Gateway |
| PyJWT | JWT generation and validation |
| Flask-Limiter | IP-based rate limiting |
| SQLite | User, session, log and test-result storage |
| HTML/CSS | Security monitoring dashboard |
| Postman | API testing and validation |
| Kali Linux | Development and testing environment |

---

## Key Features

### 1. Database-Backed Authentication

* User credentials are validated against the SQLite database.
* Supports different user roles.
* Eliminates dependency on fixed login credentials.

### 2. JWT Authentication

* Generates signed JWT tokens after successful login.
* Validates tokens before allowing access to protected API resources.
* Handles missing, invalid, expired, and revoked authentication attempts.

### 3. Access and Refresh Tokens

* Access tokens are used to access protected resources.
* Refresh tokens are used to obtain new authentication credentials.
* Provides improved token lifecycle management.

### 4. Role-Based Access Control (RBAC)

The system supports:

* **Admin**
* **User**

Administrative resources are restricted to users with the required Admin role. Unauthorized role access returns:

```text
403 Forbidden
```

### 5. Session Revocation and Logout

* Authenticated users can log out of the system.
* Sessions can be revoked.
* Requests associated with revoked sessions are rejected.
* Prevents reuse of invalidated authentication sessions.

### 6. Rate Limiting

The protected `/data` endpoint is limited to:

```text
5 requests per minute per IP address
```

Requests exceeding the configured limit receive:

```text
429 Too Many Requests
```

### 7. Security Event Logging

Security-related activities are recorded in SQLite.

Logged events can include:

* Successful resource access
* Token refresh
* Logout
* Rate-limit violations
* Access denial
* Revoked-token attempts

### 8. Security Monitoring Dashboard

A web-based dashboard provides a consolidated view of:

* Total security tests
* Passed tests
* Failed tests
* Overall validation status
* Expected and actual HTTP responses
* Recent security events

---

## API Endpoints

The application contains endpoints for the major security operations, including:

| Endpoint | Purpose |
|---|---|
| `/login` | User authentication and JWT generation |
| `/data` | Protected API resource |
| `/admin` | Admin-only protected resource |
| `/refresh` | Refresh token handling |
| `/logout` | Logout and session revocation |
| `/dashboard` | Security validation and monitoring dashboard |

> HTTP methods and authentication requirements are enforced according to the implementation of each endpoint.

---

## Project Structure

The project contains the Flask application, database components, static resources, templates, and supporting files required to operate the Secure API Gateway.

```text
jwt_api_gateway/
│
├── app.py
├── database.py
├── init_db.py
├── requirements.txt
├── static/
│   └── dashboard.css
├── templates/
│   └── dashboard.html
└── README.md
```

Runtime database and environment-specific files should not be committed to the repository.

---

## How to Run the Project

### Step 1: Clone the Repository

```bash
git clone https://github.com/Rachita780/Design-and-Implementation-of-a-Secure-API-Gateway-Using-JWT-Authentication-and-Rate-Limiting.git
```

Enter the project directory:

```bash
cd Design-and-Implementation-of-a-Secure-API-Gateway-Using-JWT-Authentication-and-Rate-Limiting
```

### Step 2: Create a Virtual Environment

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Initialize the Database

If required by the local setup:

```bash
python init_db.py
```

### Step 5: Run the Flask Application

```bash
python app.py
```

The Flask server runs locally at:

```text
http://127.0.0.1:5000
```

The security dashboard can be accessed through:

```text
http://127.0.0.1:5000/dashboard
```

---

## Testing and Validation

The Secure API Gateway was tested using **Postman** with both positive and negative security scenarios.

The validation covered:

* Admin login
* Protected data access
* Missing token
* Invalid token
* Admin access
* User login
* RBAC enforcement
* Refresh token
* Rate limiting
* Security logging
* Logout
* Revoked token access

### Validation Results

| Result | Value |
|---|---:|
| Total Tests | 12 |
| Passed | 12 |
| Failed | 0 |
| Success Rate | 100% |

All **12 functional security test cases** produced the expected HTTP responses in the local testing environment.

---

## HTTP Security Responses

The implementation demonstrates several important HTTP response codes:

| HTTP Code | Meaning | Example |
|---|---|---|
| `200 OK` | Request successful | Login or authorized access |
| `401 Unauthorized` | Authentication failed | Missing, invalid or revoked token |
| `403 Forbidden` | Insufficient permission | User attempting Admin-only access |
| `429 Too Many Requests` | Rate limit exceeded | More than configured request limit |

---

## Security Implementation Highlights

* Database-backed user authentication
* JWT access and refresh tokens
* Token validation and expiration handling
* Role-Based Access Control (RBAC)
* Admin and User roles
* Logout functionality
* Session/token revocation
* IP-based rate limiting
* Persistent security event logging
* SQLite database integration
* Functional security validation
* Web-based security monitoring dashboard

---

## Current Limitations

* The project is currently implemented and tested in a local development environment.
* Rate limiting uses a fixed request policy rather than dynamic risk-based limits.
* SQLite is suitable for the current prototype but may require replacement for large-scale deployments.
* The monitoring dashboard provides local security visibility rather than enterprise-level centralized monitoring.
* HTTPS/TLS and production-grade deployment infrastructure are outside the current prototype environment.

---

## Future Enhancements

Future improvements may include:

* HTTPS/TLS deployment
* OAuth 2.0 or OpenID Connect integration
* Dynamic and user-specific rate limiting
* Advanced security analytics and alerting
* Stronger credential and secret management
* Centralized monitoring and SIEM integration
* Production database integration
* Containerized and cloud-based deployment
* Scalable distributed rate limiting

---

## Conclusion

The project demonstrates how multiple API security mechanisms can be integrated into a single Flask-based API Gateway. By combining **JWT authentication, RBAC, token lifecycle management, session revocation, rate limiting, SQLite-based security logging, and a monitoring dashboard**, the implementation provides a practical demonstration of layered REST API security.

The completed validation confirms that the implemented security controls operate as expected within the defined local testing environment.
