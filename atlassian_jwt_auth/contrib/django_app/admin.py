from django.contrib import admin

from atlassian_jwt_auth.contrib.django_app.models import Issuer


class IssuerAdmin(admin.ModelAdmin):
    list_display = ('issuer', 'user', 'created')
    fields = ('issuer', 'user',)
    ordering = ('-created',)


admin.site.register(Issuer, IssuerAdmin)
