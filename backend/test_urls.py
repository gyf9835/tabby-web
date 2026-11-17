from django.urls import path

from tabby.app.mcp_server.views import mcp_endpoint

urlpatterns = [
    path("mcp", mcp_endpoint),
    path("mcp/", mcp_endpoint),
]
