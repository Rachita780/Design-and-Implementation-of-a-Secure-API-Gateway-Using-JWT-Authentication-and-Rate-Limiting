# Secure API Gateway with JWT Authentication and Rate Limiting

## Project Description
This project implements a secure REST API using Flask with JWT-based authentication
and rate limiting to prevent unauthorized access and abuse.

## Technologies Used
- Python
- Flask
- JSON Web Token (JWT)
- Flask-Limiter
- Postman (for testing)

## Features
- User login with JWT token generation
- Protected API endpoints
- Token validation and expiration
- Rate limiting to prevent brute-force and DoS attacks

## How to Run the Project

1. Clone the repository
2. Install dependencies:
   pip install -r requirements.txt
3. Run the application:
   python app.py

## API Endpoints
- POST /login → Generates JWT token
- GET /data → Protected endpoint (requires JWT)

## Author
Rachita
