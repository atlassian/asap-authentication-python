from django.http import HttpResponse

from atlassian_jwt_auth.contrib.django.decorators import (requires_asap,
                                                          validate_asap)


@requires_asap(issuers=['client-app'])
def expected_view(request):
    return HttpResponse('Greatest Success!')


@requires_asap(issuers=['unexpected'])
def unexpected_view(request):
    return HttpResponse('This should fail.')


@requires_asap(issuers=['whitelist'])
def decorated_view(request):
    return HttpResponse('Only the right issuer is allowed.')


@requires_asap()
def settings_view(request):
    return HttpResponse('Any settings issuer is allowed.')


@validate_asap()
def needed_view(request):
    return HttpResponse('one')


@validate_asap(required=False)
def unneeded_view(request):
    return HttpResponse('two')


@validate_asap(issuers=['whitelist'])
def restricted_issuer_view(request):
    return HttpResponse('three')


@validate_asap(subjects=['client-app'])
def restricted_subject_view(request):
    return HttpResponse('four')
