import os

def get_config_dir() -> str:
    """Get the configuration directory path."""
    return os.path.expanduser("~/.config/NoteIST")

def get_data_dir() -> str:
    """Get the data directory path."""
    return os.path.expanduser("~/.local/share/NoteIST")

def get_notes_dir() -> str:
    """Get the notes directory path."""
    return os.path.join(get_data_dir(), "notes")