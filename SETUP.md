# TRACER Framework Setup Guide

## Overview
TRACER PAL now supports both CLI and REST API modes for network path analysis. This guide covers setting up both environments. Current REST state is a local virtual environment backend. Something more substantial coming soon.

## Prerequisites
- Python 3.11 or higher
- Git (for cloning the repository)
- Basic command line knowledge

## Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/steveinit/TRACER-framework.git
cd TRACER-framework
```

### 2. Choose Your Mode

#### CLI Mode (Original)
```bash
# Run directly with system Python
python3 tracer.py
```

#### API Mode (Web/REST)
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install API dependencies
pip install -r requirements.txt

# Configure storage backend (see Storage Configuration below)
cp .env.example .env
# Edit .env with your settings

# Start the API server
python api.py
```

## API Server Details

### Starting the Server
```bash
source venv/bin/activate
python api.py
```

The server will start on `http://localhost:8000`

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| GET | `/cases` | List all cases |
| GET | `/cases/{case_id}` | Get case details |
| POST | `/cases` | Create new case |
| POST | `/cases/{case_id}/elements` | Add network element |
| GET | `/cases/{case_id}/report` | Generate case report |

### Interactive Documentation
Visit `http://localhost:8000/docs` for Swagger UI with interactive API testing.

## Storage Configuration

TRACER PAL supports multiple storage backends that auto-detect based on configuration:

### Option 1: JSON Storage (Default)
- **Use case**: Development, small teams, simple deployment
- **Setup**: No additional configuration needed
- **Data location**: Local JSON files (`tracer_database.json`)

```bash
# .env file
STORAGE_TYPE=json
# or just omit MONGODB_URL
```

### Option 2: MongoDB Atlas (Cloud)
- **Use case**: Production, team collaboration, scalable storage
- **Setup**: Create MongoDB Atlas account and cluster

#### MongoDB Atlas Setup:
1. Go to [mongodb.com/atlas](https://mongodb.com/atlas)
2. Create free account and cluster (M0 tier is free)
3. Create database user with read/write access
4. Add your IP to whitelist (or 0.0.0.0/0 for development)
5. Get connection string from "Connect" → "Connect your application"

#### Configuration:
```bash
# .env file
STORAGE_TYPE=mongo
MONGODB_URL=mongodb+srv://username:password@cluster.mongodb.net
MONGODB_DATABASE=tracer
```

### Option 3: Local MongoDB
- **Use case**: Development with MongoDB features, offline work
- **Setup**: Run MongoDB locally or via Docker

#### Using Docker Compose:
```bash
# Start local MongoDB + API
docker-compose up -d

# Uses: docker-compose.yml (includes local MongoDB)
```

#### Manual MongoDB Setup:
```bash
# Install and start MongoDB locally
# Then configure:
STORAGE_TYPE=mongo
MONGODB_URL=mongodb://localhost:27017
```

### Storage Auto-Detection

The system automatically chooses storage backend based on:

1. **`STORAGE_TYPE=mongo`** + valid `MONGODB_URL` → MongoDB
2. **`STORAGE_TYPE=json`** → JSON files
3. **Auto mode** (default): MongoDB if `MONGODB_URL` exists, otherwise JSON
4. **Fallback**: Always falls back to JSON if MongoDB connection fails

## Environment Variable Reference

### For Development (.env file):
```bash
# Storage
STORAGE_TYPE=auto          # auto, json, mongo
MONGODB_URL=               # MongoDB connection string
MONGODB_DATABASE=tracer    # Database name

# API Configuration
CORS_ORIGINS=*             # Comma-separated origins
LOG_LEVEL=info             # debug, info, warning, error
API_HOST=0.0.0.0          # Bind address
API_PORT=8000             # Port number
```

### For Docker Deployment:
```bash
# Pass environment variables to container
docker run -e MONGODB_URL="mongodb+srv://user:pass@cluster.mongodb.net" \
           -e STORAGE_TYPE=mongo \
           -p 8000:8000 tracer-api
```

### For Kubernetes Deployment:
```yaml
# Create secret for sensitive data
kubectl create secret generic tracer-secrets \
  --from-literal=mongodb-url="mongodb+srv://user:pass@cluster.mongodb.net"

# Reference in deployment
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: tracer-api
        env:
        - name: MONGODB_URL
          valueFrom:
            secretKeyRef:
              name: tracer-secrets
              key: mongodb-url
        - name: STORAGE_TYPE
          value: "mongo"
```

## Docker Deployment Options

### Local Development with MongoDB:
```bash
docker-compose up -d                    # Local MongoDB + API
```

### Production with MongoDB Atlas:
```bash
# Set your Atlas URL
export MONGODB_URL="mongodb+srv://user:pass@cluster.mongodb.net"
docker-compose -f docker-compose.atlas.yml up -d
```

### JSON-only deployment:
```bash
docker-compose -f docker-compose.json.yml up -d
```

## API Usage Examples

### Create a New Case (to be front-ended)
```bash
curl -X POST http://localhost:8000/cases \
  -H "Content-Type: application/json" \
  -d '{
    "initial_detection": {
      "threat_type": "SQL Injection",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.50"
    },
    "network_elements": [
      {
        "element_type": "firewall",
        "name": "ASA-5525",
        "movement_type": "direct",
        "source_info": {"interface": "GigabitEthernet0/1"},
        "destination_info": {"interface": "GigabitEthernet0/2"}
      }
    ]
  }'
```

### List All Cases
```bash
curl -X GET http://localhost:8000/cases
```

### Get Case Report
```bash
curl -X GET http://localhost:8000/cases/CASE_20250929_181545/report
```

## Data Storage

Both CLI and API modes use the same JSON storage backend:
- `tracer_database.json` - Main case database
- `tracer_log_*.json` - Real-time analysis logs
- Individual case export files as needed

## Dependencies

### CLI Mode
- Python 3.11+ (built-in libraries only)
- No additional dependencies required

### API Mode
- fastapi==0.104.1
- uvicorn[standard]==0.24.0
- python-multipart==0.0.6

## Troubleshooting

### Virtual Environment Issues
If you get "externally-managed-environment" error:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Port Already in Use
If port 8000 is busy, modify `api.py` line 204:
```python
uvicorn.run(app, host="0.0.0.0", port=8001)  # Change port
```

### Permission Issues
Ensure the directory is writable for JSON file creation:
```bash
chmod 755 /path/to/TRACER-framework
```

## Development Notes

### Architecture
- **CLI Mode**: Direct interaction with `NetworkPathAnalyzer` class
- **API Mode**: FastAPI wrapper around existing CLI functionality
- **Storage**: Shared JSON backend via `StorageInterface` abstraction
- **Zero Refactoring**: API mode reuses existing CLI code completely

### Frontend Integration
The API is designed for easy frontend integration:
- CORS enabled for cross-origin requests
- RESTful JSON endpoints
- Pydantic models for type safety
- Auto-generated OpenAPI documentation

## Support

- **Issues**: https://github.com/steveinit/TRACER-framework/issues
- **CLI Usage**: See README.md for detailed CLI examples
- **API Documentation**: Visit `/docs` endpoint when server is running