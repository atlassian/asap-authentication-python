from django.apps import AppConfig


class ASAPAuthConfig(AppConfig):
    name = 'atlassian_jwt_auth.contrib.django_app'
    label = 'atlassian_jwt_auth'
    verbose_name = "Atlassian Server-to-Service Authentication (ASAP)"
