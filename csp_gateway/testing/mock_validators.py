def mock_api_key_validator_valid(api_key: str, settings, module) -> dict:
    """A mock validator that accepts specific API keys and returns an identity dict."""
    valid_keys = {
        "valid_key_1": {"user": "alice", "role": "admin"},
        "valid_key_2": {"user": "bob", "role": "viewer"},
    }
    return valid_keys.get(api_key)


def mock_api_key_validator_invalid(api_key: str, settings, module) -> dict:
    """A mock validator that always returns None (invalid key)."""
    return None


def mock_api_key_validator_raises(api_key: str, settings, module) -> dict:
    """A mock validator that raises an exception."""
    raise ValueError("External validation service error")


def mock_api_key_validator_admin(api_key: str, settings, module) -> dict:
    """A mock validator that only accepts admin_key."""
    if api_key == "admin_key":
        return {"user": "admin", "role": "superadmin"}
    return None


def mock_api_key_validator_by_user(api_key: str, settings, module) -> dict:
    """A mock validator that maps user-specific API keys to identities."""
    users = {
        "alice_key": {"user": "alice", "role": "admin"},
        "bob_key": {"user": "bob", "role": "viewer"},
        "charlie_key": {"user": "charlie", "role": "viewer"},
    }
    return users.get(api_key)


def mock_simple_auth_validator_valid(username: str, password: str, settings, module) -> dict:
    """A mock validator that accepts specific credentials."""
    valid_users = {
        ("alice", "alicepass"): {"user": "alice", "role": "admin"},
        ("bob", "bobpass"): {"user": "bob", "role": "viewer"},
    }
    return valid_users.get((username, password))


def mock_simple_auth_validator_invalid(username: str, password: str, settings, module) -> dict:
    """A mock validator that always returns None (invalid credentials)."""
    return None


def mock_simple_auth_validator_raises(username: str, password: str, settings, module) -> dict:
    """A mock validator that raises an exception."""
    raise ValueError("External validation service error")


# Non-callable constant for testing that external_validator must be callable
NON_CALLABLE = "I am not callable"
