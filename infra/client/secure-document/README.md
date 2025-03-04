# Network and Computer Security
https://docs.python.org/3/library/crypto.html


# Secure Document Encryption Tool

## Overview
This tool provides cryptographic security for JSON documents using Python's `cryptography` library.

## Features
- Encrypt JSON documents with a password
- Decrypt protected documents
- Check document protection status
- Command-line interface

## Installation
```bash
pip install .
```

## Usage

### Protect a Document
```bash
secure-document protect input.json password output_encrypted.json
```

### Check Document Integrity
```bash
secure-document check input.json
```

### Unprotect a Document
```bash
secure-document unprotect input_encrypted.json password output_decrypted.json
```

## Requirements
- Python 3.7+
- cryptography library