# Meetinity API Gateway

This repository contains the API Gateway for the Meetinity platform, serving as the central entry point for all client requests and routing them to appropriate microservices.

## Overview

The API Gateway is built with **Python Flask** and provides essential features like request routing, JWT authentication, rate limiting, and CORS handling. It acts as a reverse proxy and security layer for the Meetinity microservices architecture.

## Features

- **Request Routing**: Intelligent routing of requests to appropriate backend services
- **JWT Authentication**: Secure token-based authentication with middleware validation
- **Rate Limiting**: Configurable rate limiting to prevent abuse and ensure service stability
- **CORS Support**: Cross-Origin Resource Sharing configuration for web clients
- **Health Monitoring**: Health check endpoints for service monitoring and load balancing
- **Error Handling**: Standardized error responses and exception handling

## Tech Stack

- **Flask**: Lightweight Python web framework
- **Flask-CORS**: Cross-Origin Resource Sharing support
- **Flask-Limiter**: Rate limiting functionality
- **PyJWT**: JSON Web Token implementation
- **Requests**: HTTP library for upstream service communication
- **Python-dotenv**: Environment variable management

## Project Status

- **Progress**: 40%
- **Completed Features**: Basic routing, JWT middleware, rate limiting, CORS configuration, health checks
- **Pending Features**: Service discovery, load balancing, request/response transformation, comprehensive logging

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env  # update values if needed
python src/app.py
```

## Testing

```bash
pytest
flake8
```

## Configuration

The gateway uses environment variables for configuration:

- `USER_SERVICE_URL`: URL of the user service
- `JWT_SECRET`: Secret key for JWT token validation
- `CORS_ORIGINS`: Comma-separated list of allowed CORS origins
- `RATE_LIMIT_AUTH`: Rate limit for authentication endpoints (default: "10/minute")

## API Routes

- `GET /health` - Health check endpoint
- `POST /api/auth/*` - Authentication routes (rate limited)
- `GET|POST|PUT|DELETE /api/users/*` - User management routes (JWT protected)
- `GET|POST|PUT|DELETE /api/profile/*` - Profile management routes (JWT protected)
