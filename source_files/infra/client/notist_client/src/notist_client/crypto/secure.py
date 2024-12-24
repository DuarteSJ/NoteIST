from typing import Dict, Any
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class SecureHandler:
    """Handles secure operations like signing and verifying data."""

    @staticmethod
    def sign_request(request_data: Dict[str, Any], private_key) -> str:
        """Signs request data with a private key."""
        try:
            serialized_data = json.dumps(
                request_data, separators=(",", ":"), sort_keys=True
            )
            signature = private_key.sign(
                serialized_data.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            raise Exception(f"Error signing request: {e}")

    @staticmethod
    def create_unsigned_payload(
        req_type: str, username: str, request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates an unsigned request payload."""
        return {
            "type": req_type,
            "username": username,
            "data": request_data,
        }

    @staticmethod
    def create_signed_payload(
        req_type: str, username: str, request_data: Dict[str, Any], signature: str
    ) -> Dict[str, Any]:
        """Creates a signed request payload."""
        return {
            "type": req_type,
            "username": username,
            "signature": signature,
            "data": request_data,
        }
