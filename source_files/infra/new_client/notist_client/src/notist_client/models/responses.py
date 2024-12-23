from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class Response(BaseModel):
    """Model for server responses."""
    status: str
    message: str
    documents: Optional[List[Dict[str, Any]]] = None
    document: Optional[Dict[str, Any]] = None