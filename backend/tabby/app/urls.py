from django.urls import path, include

from . import api
from . import views
from .mcp_server.views import mcp_endpoint


urlpatterns = [
    *[
        path(p, views.IndexView.as_view())
        for p in ["", "login", "app", "about", "about/features"]
    ],
    path("app-dist/<version>/<path:path>", views.AppDistView.as_view()),
    path("terminal", views.TerminalView.as_view()),
    path("demo", views.DemoView.as_view()),
    path("mcp", mcp_endpoint),
    path("mcp/", mcp_endpoint),
    path("", include(api.urlpatterns)),
]
