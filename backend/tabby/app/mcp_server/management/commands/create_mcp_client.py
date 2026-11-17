from django.core.management.base import BaseCommand

from tabby.app.mcp_server.models import McpClient


class Command(BaseCommand):
    help = "Create an MCP client identity (optionally restricted to Tabby profile groups)"

    def add_arguments(self, parser):
        parser.add_argument("name")
        parser.add_argument(
            "--groups",
            default="",
            help="comma-separated Tabby profile groups; empty = unrestricted",
        )
        parser.add_argument("--disable", action="store_true", help="create disabled")

    def handle(self, *args, **opts):
        groups = [g.strip() for g in opts["groups"].split(",") if g.strip()]
        client, created = McpClient.objects.get_or_create(
            name=opts["name"],
            defaults={
                "allowed_groups": groups or None,
                "enabled": not opts["disable"],
            },
        )
        if not created:
            client.allowed_groups = groups or None
            client.enabled = not opts["disable"]
            client.save()
        action = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(f"MCP client '{client.name}' {action}"))
        self.stdout.write(f"token: {client.token}")
        self.stdout.write(f"allowed_groups: {client.allowed_groups or '(all)'}")
