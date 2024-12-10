from pydantic import BaseModel
from typing import Optional
from enum import Enum

class OperationType(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"

class RequestModel(BaseModel):
    operation: OperationType
    document: Optional[dict] = None
    document_id: Optional[str] = None

class ResponseModel(BaseModel):
    status: str
    message: str
    document: Optional[dict] = None

class DocumentModel(BaseModel):
    name: str
    content: str

def convert_objectid(value):
    return str(value) if isinstance(value, ObjectId) else value
