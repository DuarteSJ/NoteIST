from typing import Optional, List
from enum import Enum

from pydantic import BaseModel, Field, GetCoreSchemaHandler, field_validator
from bson import ObjectId
from pydantic_core import CoreSchema, core_schema
import datetime

from enum import Enum
from typing import Optional, List, Union, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing_extensions import Annotated

class RequestType(Enum):
    CREATE_NOTE = "create_note"
    GET_NOTE = "get_note"
    GET_USER_NOTES = "get_user_notes"
    EDIT_NOTE = "edit_note"
    DELETE_NOTE = "delete_note"

# Abstract Base Request Model
class BaseRequestModel(BaseModel):
    """
    Abstract base class for all request models.
    Provides common validation and structure.
    """
    type: RequestType

    class Config:
        extra = "allow"  # Allow extra fields for flexibility

# Specific Request Models
class CreateNoteRequest(BaseRequestModel):
    type: RequestType = RequestType.CREATE_NOTE
    document: Dict[str, Any]

class GetNoteRequest(BaseRequestModel):
    type: RequestType = RequestType.GET_NOTE
    username: str
    note_id: str

class GetUserNotesRequest(BaseRequestModel):
    type: RequestType = RequestType.GET_USER_NOTES
    username: str

class EditNoteRequest(BaseRequestModel):
    type: RequestType = RequestType.EDIT_NOTE
    note_id: str
    document: Dict[str, Any]

class DeleteNoteRequest(BaseRequestModel):
    type: RequestType = RequestType.DELETE_NOTE
    note_id: str

# Union type for all possible request models
RequestModelType = Union[
    CreateNoteRequest,
    GetNoteRequest,
    GetUserNotesRequest,
    EditNoteRequest,
    DeleteNoteRequest
]

# Request Factory
class RequestFactory:
    @staticmethod
    def create_request(request_data: Dict[str, Any]) -> RequestModelType:
        """
        Create the appropriate request model based on the request type.

        :param request_data: Dictionary containing request details
        :return: Specific request model instance
        """
        request_type = request_data.get('type')

        request_map = {
            RequestType.CREATE_NOTE: CreateNoteRequest,
            RequestType.GET_NOTE: GetNoteRequest,
            RequestType.GET_USER_NOTES: GetUserNotesRequest,
            RequestType.EDIT_NOTE: EditNoteRequest,
            RequestType.DELETE_NOTE: DeleteNoteRequest
        }

        request_class = request_map.get(request_type)
        if not request_class:
            raise ValueError(f"Unsupported request type: {request_type}")

        return request_class(**request_data)

# Response Model
class ResponseModel(BaseModel):
    status: str
    message: str
    documents: Optional[List[Dict[str, Any]]] = None
    document: Optional[Dict[str, Any]] = None

def convert_objectid(value):
    return str(value) if isinstance(value, ObjectId) else value

class PyObjectId(ObjectId):
    """Custom type for handling MongoDB ObjectId in Pydantic models"""
    
    @classmethod
    def validate(cls, v, _handler=None):
        """
        Validator method that matches Pydantic's expected signature.
        The additional _handler parameter allows for compatibility with Pydantic's validation process.
        """
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)
    
    @classmethod
    def __get_pydantic_core_schema__(
        cls, 
        source_type: type, 
        handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Provides a Pydantic core schema for validation.
        This replaces the older __get_validators__ method.
        """
        return core_schema.union_schema([
            core_schema.str_schema(),
            core_schema.is_instance_schema(ObjectId)
        ])

class UsersModel(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    username: str = Field(...)
    public_key: bytes = Field(...) #TODO: temos de mudar isto? Acho que é chill, mas n sei
    owned_notes: List[int] = Field(...)
    editor_notes: List[int] = Field(...)
    viewer_notes: List[int] = Field(...)

class NotesModel(BaseModel):
    """Pydantic model for documents"""

    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    hmac: str = Field(...)
    title: str = Field(...)
    content: str = Field(...)
    owner: int = Field(...)
    editors: List[int] = Field(...)
    viewers: List[int] = Field(...)
    date_created: datetime.datetime = Field(...)
    date_modified: datetime.datetime = Field(...)
    last_modified_by: int = Field(...)
    version: int = Field(...)

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat() + "Z"}

        # TODO: podemos apagar este garbage por favor?????
        schema_extra = {
            "id": 123,
            "title": "Example Document",
            "note": "This is an example document.",
            "data_created": "2022-01-01T12:00:00Z",
            "date_modified": "2022-01-02T12:00:00Z",
            "last_modified_by": 456,
            "version": 3,
            "owner": {
                "id": 456,
                "username": "john"
            },
            "editors": [
                {
                "id": 789,
                "username": "jane"
                },
                {
                "id": 1011,
                "username": "bob"
                }
            ],
            "viewers": [
                {
                "id": 1213,
                "username": "alice"
                },
                {
                "id": 1415,
                "username": "charlie"
                }
            ]
        }
