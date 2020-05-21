import warnings

from .decorators import requires_asap  # noqa


warnings.warn(
    "The atlassian_jwt_auth.contrib.flask_app package is deprecated in 4.0.0 "
    "in favour of atlassian_jwt_auth.frameworks.flask.",
    DeprecationWarning, stacklevel=2
)
