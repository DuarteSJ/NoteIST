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
    content: str = Field(...)

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "title": "Sample Document",
                "content": "This is a sample document content",
            }
        }
