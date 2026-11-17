"""Local dev seed: synthetic encrypted config + MCP clients (NO real data)."""
import base64, json, os, sys
import django, yaml

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tabby.settings")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from django.contrib.auth import get_user_model
from tabby.app.models import Config
from tabby.app.mcp_server.models import McpClient

PROFILES = [
    {"id": "11111111-1111-1111-1111-111111111111", "type": "ssh", "name": "home-lxc", "group": "home",
     "host": "127.0.0.1", "port": 2201, "user": "dev", "auth": {"type": "key", "id": "aaaaaaaa-1111-1111-1111-111111111111"}},
    {"id": "22222222-2222-2222-2222-222222222222", "type": "ssh", "name": "fake-vps", "group": "vps",
     "host": "127.0.0.1", "port": 2202, "user": "dev", "auth": None},
]
PRIVKEY = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dev_test_ssh_key"), encoding="utf-8").read()
SECRETS = [{"type": "key", "key": {"id": "aaaaaaaa-1111-1111-1111-111111111111"}, "value": PRIVKEY}]

def encrypt_yaml(password):
    salt, iv = os.urandom(8), os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 100000, dklen=32)
    pt = json.dumps({"config": {"profiles": PROFILES}, "secrets": SECRETS})
    p = PKCS7(128).padder(); padded = p.update(pt.encode()) + p.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    blob = c.update(padded) + c.finalize()
    return yaml.dump({"encrypted": True, "vault": {"version": 1,
        "contents": base64.b64encode(blob).decode(),
        "keySalt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode()}, "configSync": {"configID": 1}})

import hashlib
U = get_user_model()
u, _ = U.objects.get_or_create(username="admin", defaults={"config_sync_token": "dev-sync-token-0000000000000000000000000000000000000000000000000000000000000000"})
Config.objects.filter(user=u, name="dev-synthetic").delete()
Config.objects.create(user=u, name="dev-synthetic", content=encrypt_yaml("dev-vault-pass"))
u.active_config = Config.objects.get(user=u, name="dev-synthetic"); u.save()
all_c, created1 = McpClient.objects.get_or_create(name="dev-all")
home_c, created2 = McpClient.objects.get_or_create(name="dev-home", defaults={"allowed_groups": ["home"]})
print("sync_token:", u.config_sync_token[:16], "...")
print("dev-all token:", all_c.token)
print("dev-home token:", home_c.token, "groups:", home_c.allowed_groups)
