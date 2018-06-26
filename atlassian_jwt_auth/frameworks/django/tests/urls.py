from django.conf.urls import url

from atlassian_jwt_auth.frameworks.django.tests import views


urlpatterns = [
    url(r'^asap/expected$', views.expected_view, name='expected'),
    url(r'^asap/unexpected$', views.unexpected_view, name='unexpected'),
    url(r'^asap/decorated$', views.decorated_view, name='decorated'),
    url(r'^asap/settings$', views.settings_view, name='settings'),

    url(r'^asap/subject_does_not_need_to_match_issuer$',
        views.subject_does_not_need_to_match_issuer_view,
        name='subject_does_not_need_to_match_issuer'),
    url(r'^asap/subject_does_need_to_match_issuer_view$',
        views.subject_does_need_to_match_issuer_view,
        name='subject_does_need_to_match_issuer'),

    url(r'^asap/subject_does_not_need_to_match_issuer_from_settings$',
        views.subject_does_not_need_to_match_issuer_from_settings_view,
        name='subject_does_not_need_to_match_issuer_from_settings'),

    url(r'^asap/needed$', views.needed_view, name='needed'),
    url(r'^asap/unneeded$', views.unneeded_view, name='unneeded'),
    url(r'^asap/restricted_issuer$', views.restricted_issuer_view,
        name='restricted_issuer'),
    url(r'^asap/restricted_subject$', views.restricted_subject_view,
        name='restricted_subject'),

    url(r'^excluded', views.excluded, name='excluded'),
]
