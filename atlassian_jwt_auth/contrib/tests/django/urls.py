from django.conf.urls import url

from atlassian_jwt_auth.contrib.tests.django import views


urlpatterns = [
    url(r'^asap/expected$', views.expected_view, name='expected'),
    url(r'^asap/unexpected$', views.unexpected_view, name='unexpected'),
    url(r'^asap/decorated$', views.decorated_view, name='decorated'),
    url(r'^asap/settings$', views.settings_view, name='settings')
]
