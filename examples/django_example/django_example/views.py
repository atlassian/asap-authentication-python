
from atlassian_jwt_auth.contrib.django_app.decorators import asap_required


@asap_required
def protected(request):
    return 'Hello world!'
