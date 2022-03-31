from django.urls import path

from atlassian_jwt_auth.frameworks.django.tests import views


urlpatterns = [
    path('asap/expected', views.expected_view, name='expected'),
    path(r'^asap/unexpected', views.unexpected_view, name='unexpected'),
    path('^asap/decorated', views.decorated_view, name='decorated'),
    path('asap/settings', views.settings_view, name='settings'),

    path('asap/subject_does_not_need_to_match_issuer',
         views.subject_does_not_need_to_match_issuer_view,
         name='subject_does_not_need_to_match_issuer'),
    path('asap/subject_does_need_to_match_issuer_view',
         views.subject_does_need_to_match_issuer_view,
         name='subject_does_need_to_match_issuer'),

    path('asap/subject_does_not_need_to_match_issuer_from_settings',
         views.subject_does_not_need_to_match_issuer_from_settings_view,
         name='subject_does_not_need_to_match_issuer_from_settings'),

    path('asap/needed', views.needed_view, name='needed'),
    path(r'asap/unneeded', views.unneeded_view, name='unneeded'),
    path(r'asap/restricted_issuer', views.restricted_issuer_view,
         name='restricted_issuer'),
    path('asap/restricted_subject', views.restricted_subject_view,
         name='restricted_subject'),
]
