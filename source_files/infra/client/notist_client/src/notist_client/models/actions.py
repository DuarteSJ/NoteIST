from enum import Enum


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
    FINAL_PUSH ="push_final"
    PULL = "pull"
