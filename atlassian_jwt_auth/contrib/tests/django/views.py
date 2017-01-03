from django.http import HttpResponse

from atlassian_jwt_auth.contrib.django.decorators import requires_asap


@requires_asap(issuers=('client-app',))
def my_view(request):
    return HttpResponse('Greatest Success!')


@requires_asap(issuers=('unexpected',))
def unexpected_view(request):
    return HttpResponse('This should fail.')


@requires_asap(issuers=('whitelist',))
def whitelist_view(request):
    return HttpResponse('Only the right issuer is allowed.')
