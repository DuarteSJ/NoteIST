from typing import List, Dict, Any, Union
from pydantic import BaseModel
from .actions import ActionType


class BaseRequest(BaseModel):
    """Base class for all requests."""

    username: str


class SignedRequest(BaseRequest):
    """Base class for requests that require authentication."""

    signature: str


class RegisterRequest(BaseRequest):
    """Request model for user registration."""

    public_key: str


class PushRequest(SignedRequest):
    """Request model for pushing changes to the server."""

    data: List[Dict[str, Any]]


class PullRequest(SignedRequest):
    """Request model for pulling changes from the server."""

    pass


RequestModelType = Union[RegisterRequest, PushRequest, PullRequest]


class RequestFactory:
    """Factory class for creating request objects."""

    @staticmethod
    def create_request(request_data: Dict[str, Any]) -> RequestModelType:
        request_map = {
            "register": RegisterRequest,
            "push": PushRequest,
            "pull": PullRequest,
        }

        request_type = request_data.get("type")
        request_class = request_map.get(request_type)

        if not request_class:
            raise ValueError(f"Unsupported request type: {request_type}")

        return request_class(**request_data)
