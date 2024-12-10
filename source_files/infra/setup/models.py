from pydantic import BaseModel, Field, GetCoreSchemaHandler
from typing import Optional
from bson import ObjectId
from pydantic_core import CoreSchema, core_schema

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

class DocumentModel(BaseModel):
    """Pydantic model for documents"""

    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    title: str = Field(...)
    note: str = Field(alias="content")
    date_created: Optional[datetime] = Field(
        default_factory=datetime.utcnow, alias="data_created"
    )
    date_modified: Optional[datetime] = None
    last_modified_by: Optional[int] = None
    version: Optional[int] = 1
    owner: Optional[UserReference] = None
    editors: Optional[List[UserReference]] = []
    viewers: Optional[List[UserReference]] = []

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat() + "Z"}
        schema_extra = {
            "example": {
                "title": "Example Document",
                "note": "This is an example document.",
                "date_created": "2022-01-01T12:00:00Z",
                "date_modified": "2022-01-02T12:00:00Z",
                "last_modified_by": 456,
                "version": 3,
                "owner": {"id": 456, "username": "john"},
                "editors": [
                    {"id": 789, "username": "jane"},
                    {"id": 1011, "username": "bob"},
                ],
                "viewers": [
                    {"id": 1213, "username": "alice"},
                    {"id": 1415, "username": "charlie"},
                ],
            }
        }
