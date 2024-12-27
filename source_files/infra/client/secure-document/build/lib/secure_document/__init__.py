# secure_document/__init__.py
from .crypto_utils import SecureDocumentHandler
from .cli import main

__all__ = ["SecureDocumentHandler", "main"]
