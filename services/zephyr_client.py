"""Internal Zephyr service client — issues and validates service credentials."""
import uuid


def issue_service_key() -> str:
    # Mint a new Zephyr service credential for an internal caller.
    return "zephyr-" + str(uuid.uuid4())


def is_valid(token: str) -> bool:
    return token.startswith("zephyr-")
