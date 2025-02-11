# Flask JWT Authentication API

This is a simple Flask-based REST API for user registration, login, and user information retrieval using JWT (JSON Web Tokens) for authentication.

## Features

- User registration with unique username and email.
- User login with JWT token generation.
- Protected route to fetch user information using JWT authentication.
- PostgreSQL database integration.
- Password hashing for security.

### Run docker-compose

```bash
docker-compose up
```

### Examples of usage

```bash

curl -X POST -H "Content-Type: application/json" -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpassword"
}' http://localhost:5000/register

```

```bash

curl -X POST -H "Content-Type: application/json" -d '{
    "username": "testuser",
    "password": "testpassword"
}' http://localhost:5000/login

```