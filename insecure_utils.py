"""
WARNING: This file is INTENTIONALLY VULNERABLE.
It is meant only for testing security scanners. Do NOT use in production.
"""
import hashlib
import random
import tempfile

import requests
import yaml


def hash_password(password):
    # Vulnerability: weak hashing algorithm (MD5, no salt)
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    # Vulnerability: insecure random generator for security tokens
    return str(random.randint(100000, 999999))


def load_config(path):
    # Vulnerability: unsafe YAML loading (arbitrary object instantiation)
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)


def fetch_url(url):
    # Vulnerability: SSRF (user-controlled URL) + TLS verification disabled
    return requests.get(url, verify=False).text


def write_temp(data):
    # Vulnerability: insecure temporary file creation (race condition)
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write(data)
    return path


def check_admin(user):
    # Vulnerability: assert used for access control (removed with -O)
    assert user.get("is_admin"), "Access denied"
    return "Welcome admin"
