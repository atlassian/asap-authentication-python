from typing import List


def get_permitted_algorithm_names() -> List[str]:
    """returns permitted algorithm names."""
    return [
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
    ]
