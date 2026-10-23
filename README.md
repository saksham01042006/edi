# PrivTrace

PrivTrace is a policy-aware sensitive data flow analysis and leakage detection prototype built as a full-stack academic project. The application parses Python source code without executing it, traces supported direct flows and aliases, applies privacy policies, and surfaces findings with evidence and graph information.

## Features
- Static Python analysis using the `ast` module
- Sensitive-source detection for request input, password, API key, and email flows
- Direct alias propagation and assignment tracing
- Supported sink detection for logging, file writes, and outbound HTTP requests
- Policy evaluation for password logging, API destination allowlists, and sensitive logs
- FastAPI backend with SQLite persistence and JSON export
- React + Vite dashboard with analyzer and graph explorer

## Architecture
- `backend/` contains FastAPI application, SQLAlchemy models, static analyzer, and persistence helpers.
- `frontend/` contains the Vite + React dashboard and graph viewer.
- `sample_code/` is reserved for demonstration inputs.
- `tests/` contains regression tests for the static analyzer and API flow.

## Stack
- Frontend: React, TypeScript, Vite
- Backend: FastAPI, SQLAlchemy, SQLite
- Analyzer: Python `ast`
- Validation: pytest

## Prerequisites
- Python 3.10+
- Node.js 18+
- npm
- Access to local ports `8000` and `5173`

## Windows setup
1. Open PowerShell in the project root.
2. Create a virtual environment:
   `python -m venv .venv`
3. Activate it:
   `.\.venv\Scripts\Activate.ps1`
4. Install backend dependencies:
   `cd backend`
   `pip install -r requirements.txt`
5. Install frontend dependencies:
   `cd ..\frontend`
   `npm install`

## Environment configuration
Create a `.env` file in the project root using `.env.example` as a template.

## Database initialization
The application initializes the SQLite database automatically on startup and creates tables via SQLAlchemy.

## Run the backend
`cd backend`
`python -m uvicorn main:app --host 0.0.0.0 --port 8000`

## Run the frontend
`cd frontend`
`npm run dev -- --host 0.0.0.0`

## API docs
Open `http://localhost:8000/docs` after starting the backend.

## Run tests
`cd ..`
`python -m pytest tests/test_privtrace.py -q`

## Try the demonstration
Analyze the sample code in the Code Analyzer page or send a request to the backend using the demo source:

```python
def login(request):
    password = request.get("password")
    attempted_value = password
    logger.info("Login attempt: %s", attempted_value)
```

This should produce a genuine finding for the `no-password-logging` policy.

## Limitations
- The analyzer is intentionally conservative and supports only direct assignments, aliases, and a limited set of sinks.
- Dynamic runtime values, reflection, and complex interprocedural flows are out of scope.
- Policy evaluation does not prove a codebase is secure; it highlights supported paths based on static evidence.

## Troubleshooting
- If the backend cannot connect, verify the virtual environment and run the uvicorn command again.
- If the frontend cannot reach the backend, ensure CORS is enabled and the backend is running on port 8000.
- If pytest fails, confirm dependencies were installed in the active environment and run the tests again.