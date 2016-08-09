from django.conf import settings
from django.db import models
from django.utils.encoding import python_2_unicode_compatible


@python_2_unicode_compatible
class Issuer(models.Model):
    """
    Represents a valid issuer for ASAP tokens
    """
    issuer = models.CharField("Issuer", max_length=120, primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='asap_issuers',
        on_delete=models.CASCADE,
        verbose_name="User"
    )
    created = models.DateTimeField("Created", auto_now_add=True)

    class Meta:
        verbose_name = "Issuer"
        verbose_name_plural = "Issuers"

    def __str__(self):
        return self.issuer
