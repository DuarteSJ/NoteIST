from pydantic import BaseModel, Field, GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from datetime import datetime
from enum import Enum
from typing import Optional, List, Union, Dict, Any


class ActionType(Enum):
    """Enum for different note-related actions"""

    CREATE_NOTE = "create_note"
    EDIT_NOTE = "edit_note"
    DELETE_NOTE = "delete_note"
    ADD_COLLABORATOR = "add_collaborator"
    REMOVE_COLLABORATOR = "remove_collaborator"


class RequestType(Enum):
    """Enum for different request types"""

    REGISTER = "register"
    PUSH = "push"
    PUSH_FINAL = "push_final"
    PULL = "pull"


class BaseRequestModel(BaseModel):
    """
    Base request model for all request types.
    Provides common structure for pull, push, and register requests.
    """

    username: str
    type: RequestType
    data: Union[List[Dict[str, Any]], Dict[str, Any]]


class SignedRequestModel(BaseRequestModel):
    """
    Request model that includes a signature.
    Used for requests that require authentication.
    """

    signature: bytes


class RegisterRequest(BaseRequestModel):
    """
    Request model for user registration.
    Includes username and public key.
    """

    type: RequestType = RequestType.REGISTER


class PushRequest(SignedRequestModel):
    """
    Request model for push operations.
    Includes a list of actions to be performed.
    """

    type: RequestType = RequestType.PUSH


class PushFinalRequest(SignedRequestModel):

    type: RequestType = RequestType.PUSH_FINAL


class PullRequest(SignedRequestModel):
    """
    Request model for pull operations.
    Retrieves data based on username and signature.
    """

    type: RequestType = RequestType.PULL


# Union type for all possible request models
RequestModelType = Union[RegisterRequest, PushRequest, PullRequest]


class RequestFactory:
    @staticmethod
    def create_request(request_data: Dict[str, Any]):
        """
        Create the appropriate request model based on the request type.

        :param request_data: Dictionary containing request details
        :return: Specific request model instance
        """

        request_type = request_data.get("type")

        request_map = {
            RequestType.REGISTER.value: RegisterRequest,
            RequestType.PUSH.value: PushRequest,
            RequestType.PULL.value: PullRequest,
            RequestType.PUSH_FINAL.value: PushFinalRequest,
        }

        request_class = request_map.get(request_type)
        if not request_class:
            raise ValueError(f"Unsupported request type: {request_type}")

        return request_class(**request_data)


class ResponseModel(BaseModel):
    status: str
    message: str
    digest_of_hashes: Optional[str] = None
    documents: Optional[List[Dict[str, Any]]] = None
    document: Optional[Dict[str, Any]] = None
    curr_noteid: Optional[int] = None
    keys: Optional[List[Dict[str, Any]]] = None


class UsersModel(BaseModel):
    id: str = Field(...)
    username: str = Field(...)
    public_key: bytes = Field(...)
    owned_notes: List[int] = Field(...)
    editor_notes: List[int] = Field(...)
    viewer_notes: List[int] = Field(...)
    keys: Dict[str, bytes] = Field(...)
    last_request: str = Field(...)


class NotesModel(BaseModel):
    id: str = Field(...)
    hmac: str = Field(...)
    title: str = Field(...)
    content: str = Field(...)
    owner: int = Field(...)
    editors: List[int] = Field(...)
    viewers: List[int] = Field(...)
    date_created: datetime = Field(...)
    date_modified: datetime = Field(...)
    last_modified_by: int = Field(...)
    version: int = Field(...)
