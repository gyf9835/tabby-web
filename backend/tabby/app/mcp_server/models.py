import secrets

from django.db import models


def _default_groups():
    return None


class McpClient(models.Model):
    """An MCP client identity allowed to call the /mcp endpoint.

    allowed_groups == null  -> unrestricted (all servers, including ungrouped)
    allowed_groups == [..]  -> only servers whose Tabby profile group is listed
    """

    name = models.CharField(max_length=64, unique=True)
    token = models.CharField(max_length=64, unique=True, editable=False)
    allowed_groups = models.JSONField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_hex(32)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
