from django.conf.urls import url

from atlassian_jwt_auth.contrib.tests.django import views


urlpatterns = [
    url(r'^asap/test1', views.my_view),
    url(r'^asap/unexpected', views.unexpected_view),
    url(r'^asap/whitelist', views.whitelist_view)
]
