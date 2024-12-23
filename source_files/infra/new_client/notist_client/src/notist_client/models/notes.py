from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from bson import ObjectId

class PyObjectId(ObjectId):
    """Custom type for handling MongoDB ObjectId."""
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

class Note(BaseModel):
    """Represents a note in the system."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    title: str
    content: str
    owner: str
    editors: List[str] = Field(default_factory=list)
    viewers: List[str] = Field(default_factory=list)
    version: int
    date_created: datetime = Field(default_factory=datetime.utcnow)
    date_modified: datetime = Field(default_factory=datetime.utcnow)
    last_modified_by: str

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda dt: dt.isoformat() + "Z"
        }

class User(BaseModel):
    """Represents a user in the system."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    username: str
    public_key: bytes
    owned_notes: List[int] = Field(default_factory=list)
    editor_notes: List[int] = Field(default_factory=list)
    viewer_notes: List[int] = Field(default_factory=list)