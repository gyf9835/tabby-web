"""Minimal Django settings for LOCAL tests of the tabby MCP server app.

Deliberately NOT the full tabby settings: only the apps the mcp_server needs,
so tests run fast and isolated (sqlite in-memory).
"""

import os

SECRET_KEY = "dev-test-key"
DEBUG = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "tabby.app",
    "tabby.app.mcp_server",
]

DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
}

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

AUTH_USER_MODEL = "app.User"
ROOT_URLCONF = "test_urls"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# MCP settings (read dynamically by the app; tests override via settings)
MCP_VAULT_PASSWORD = os.getenv("MCP_VAULT_PASSWORD")
MCP_GATEWAY_URL = os.getenv("MCP_GATEWAY_URL", "")
MCP_GATEWAY_TOKEN = os.getenv("MCP_GATEWAY_TOKEN", "")
MCP_CONNECT_MODE = os.getenv("MCP_CONNECT_MODE", "gateway")
MCP_CACHE_TTL = 0  # disable module cache in tests
