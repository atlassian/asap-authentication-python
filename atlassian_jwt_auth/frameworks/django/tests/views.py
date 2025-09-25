from django.http import HttpRequest, HttpResponse

from atlassian_jwt_auth.contrib.django.decorators import requires_asap, validate_asap
from atlassian_jwt_auth.frameworks.django import restrict_asap, with_asap


@with_asap(issuers=["client-app"])
def expected_view(request: HttpRequest):
    return HttpResponse("Greatest Success!")


@with_asap(issuers=["unexpected"])
def unexpected_view(request: HttpRequest):
    return HttpResponse("This should fail.")


@with_asap(issuers=["whitelist"])
def decorated_view(request: HttpRequest):
    return HttpResponse("Only the right issuer is allowed.")


@requires_asap()
def settings_view(request: HttpRequest):
    return HttpResponse("Any settings issuer is allowed.")


@with_asap(subject_should_match_issuer=False)
def subject_does_not_need_to_match_issuer_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse("Subject does not need to match issuer.")


@with_asap(subject_should_match_issuer=True)
def subject_does_need_to_match_issuer_view(request: HttpRequest):
    return HttpResponse("Subject does need to match issuer.")


@with_asap()
def subject_does_not_need_to_match_issuer_from_settings_view(request: HttpRequest):
    return HttpResponse("Subject does not need to match issuer (settings).")


@restrict_asap
def needed_view(request: HttpRequest):
    return HttpResponse("one")


@restrict_asap(required=False)
def unneeded_view(request: HttpRequest):
    return HttpResponse("two")


@restrict_asap(issuers=["whitelist"])
def restricted_issuer_view(request):
    return HttpResponse("three")


@validate_asap(subjects=["client-app"])
def restricted_subject_view(request: HttpRequest):
    return HttpResponse("four")
