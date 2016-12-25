from django.http import HttpResponse

from atlassian_jwt_auth.contrib.django.decorators import requires_asap


@requires_asap(issuers=('client-app',))
def my_view(request):
    return HttpResponse('Greatest Success!')
