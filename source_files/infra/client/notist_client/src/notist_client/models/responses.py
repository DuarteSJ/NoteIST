from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class Response(BaseModel):
    """Model for server responses."""

    status: str
    message: str
    action_results: Optional[List[Dict[str, Any]]] = None
    user_results: Optional[List[Dict[str, Any]]] = None
    public_keys_dict: Optional[Dict[str, Any]] = None
    documents: Optional[List[Dict[str, Any]]] = None
    document: Optional[Dict[str, Any]] = None
    keys: Optional[Dict[str, Any]] = None
