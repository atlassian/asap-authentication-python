from django.conf.urls import url

from atlassian_jwt_auth.contrib.tests.django import views


urlpatterns = [
    url(r'^asap/expected$', views.expected_view, name='expected'),
    url(r'^asap/unexpected$', views.unexpected_view, name='unexpected'),
    url(r'^asap/decorated$', views.decorated_view, name='decorated'),
    url(r'^asap/settings$', views.settings_view, name='settings'),

    url(r'^asap/needed$', views.needed_view, name='needed'),
    url(r'^asap/unneeded$', views.unneeded_view, name='unneeded'),
    url(r'^asap/restricted_issuer$', views.restricted_issuer_view,
        name='restricted_issuer'),
    url(r'^asap/restricted_subject$', views.restricted_subject_view,
        name='restricted_subject'),
]
