class SecureDocumentError(Exception):
    """Base exception for SecureDocument-related errors."""

    pass


class KeyFileNotFoundError(SecureDocumentError):
    """Raised when the key file is not found."""

    pass


class IntegrityError(SecureDocumentError):
    """Raised when file integrity or authenticity cannot be verified."""

    pass


class EncryptionError(SecureDocumentError):
    """Raised when there is an issue during encryption or decryption."""

    pass
