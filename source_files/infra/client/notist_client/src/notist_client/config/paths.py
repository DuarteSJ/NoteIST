import os


def get_config_dir() -> str:
    """Get the configuration directory path."""
    return os.path.expanduser("~/.config/NoteIST")

def get_config_file() -> str:
    """Get the configuration file path."""
    return os.path.join(get_config_dir(), "config.json")

def get_priv_key_file() -> str:
    """Get the private key file path."""
    return os.path.join(get_config_dir(), "priv_key.pem")

def get_notes_dir() -> str:
    """Get the data directory path."""
    return os.path.expanduser("~/.local/share/NoteIST/notes")
