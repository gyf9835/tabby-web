from django.contrib import admin

from .models import McpClient


@admin.register(McpClient)
class McpClientAdmin(admin.ModelAdmin):
    list_display = ("name", "token", "enabled", "allowed_groups", "created_at")
    list_editable = ("enabled",)
    readonly_fields = ("token", "created_at", "modified_at")
    search_fields = ("name", "token")
