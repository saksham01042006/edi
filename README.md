# PrivTrace

PrivTrace is a policy-aware static analyzer for tracing selected sensitive data through supported Python code. The entire application—FastAPI API, SQLite models, AST analyzer, and light-theme dashboard—is implemented in the single `app.py` file. Python source code is parsed and is never executed.

## Features
- Static Python AST analysis and direct assignment/alias tracking
- Detection of password logging, sensitive file writes, and API keys sent to unapproved destinations
- Explainable findings with source, destination, line evidence, remediation, and limitations
- Project, policy, analysis history, and JSON report API with SQLite persistence
- Interactive dashboard with analysis results and a flow graph

## Requirements
- Python 3.10+
- Install dependencies from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run the application

From the project root:

```powershell
python app.py
```

Open `http://localhost:8000`. The API documentation is available at `http://localhost:8000/docs`. To use a different port, set the `PORT` environment variable before starting the app.

The SQLite database is created automatically next to `app.py`. Set `DATABASE_URL` or `MAX_FILE_SIZE_BYTES` to override the defaults.

## Run tests

```powershell
python -m pytest tests/test_privtrace.py -q
```

## Demonstration

The dashboard starts with this example, which should produce a high-severity password-logging finding:

```python
def login(request):
    password = request.get("password")
    attempted_value = password
    logger.info("Login attempt: %s", attempted_value)
```

## Limitations
- The analyzer deliberately supports a limited set of syntax patterns, sources, aliases, and sinks.
- Dynamic runtime values, reflection, and complex interprocedural flows are not fully analyzed.
- Results are evidence of supported static paths, not a proof of security or compliance.
