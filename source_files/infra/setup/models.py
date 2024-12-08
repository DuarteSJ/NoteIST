# app/models.py
from pydantic import BaseModel, Field
from typing import Optional
from bson import ObjectId
from pydantic.json_schema import JsonSchemaValue

class PyObjectId(ObjectId):
    """Custom type for handling MongoDB ObjectId in Pydantic models"""
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: JsonSchemaValue) -> JsonSchemaValue:
        schema.update(type="string", pattern="^[a-fA-F0-9]{24}$")
        return schema

class DocumentModel(BaseModel):
    """Pydantic model for documents"""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    title: str = Field(...)
    content: str = Field(...)
    
    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }
        schema_extra = {
            "example": {
                "title": "Sample Document",
                "content": "This is a sample document content"
            }
        }