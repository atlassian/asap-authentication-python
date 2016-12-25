from django.conf.urls import url

from atlassian_jwt_auth.contrib.tests.django.views import my_view

urlpatterns = [
    url(r'^asap/test1', my_view)
]
