# tests/test_api.py
import requests
import json
import sys

# API endpoint
BASE_URL = "http://192.168.56.7:8000"

def test_crud_operations():
    """Perform comprehensive CRUD tests on the API"""
    # Test Create
    print("Testing CREATE document...")
    create_response = requests.post(
        f"{BASE_URL}/documents/", 
        json={"title": "Test Document", "content": "This is a test document"}
    )
    print("Create Response:", create_response.json())
    document_id = create_response.json()['id']
    
    # Test Read All
    print("\nTesting READ ALL documents...")
    read_all_response = requests.get(f"{BASE_URL}/documents/")
    print("Read All Response:", json.dumps(read_all_response.json(), indent=2))
    
    # Test Read Single
    print("\nTesting READ Single document...")
    read_single_response = requests.get(f"{BASE_URL}/documents/{document_id}")
    print("Read Single Response:", read_single_response.json())