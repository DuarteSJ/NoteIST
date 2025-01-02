from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class ActionType(Enum):
    """Defines the types of actions that can be performed on notes."""

    CREATE_NOTE = "create_note"
    EDIT_NOTE = "edit_note"
    DELETE_NOTE = "delete_note"
    ADD_USER = "add_collaborator"
    REMOVE_USER = "remove_collaborator"


class RequestType(Enum):
    """Defines the types of requests that can be made to the server."""

    REGISTER = "register"
    PUSH = "push"
    FINAL_PUSH = "push_final"
    PULL = "pull"


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