"""
WARNING: This file is INTENTIONALLY VULNERABLE.
It is meant only for testing security scanners. Do NOT deploy it.
"""
import logging
import xml.etree.ElementTree as ET

import jwt
from flask import Flask, redirect, render_template_string, request, make_response
from lxml import etree

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

JWT_SECRET = "changeme"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # Vulnerability: sensitive data written to logs
    logging.info("Login attempt: user=%s password=%s", username, password)
    token = jwt.encode({"user": username, "role": "user"}, JWT_SECRET, algorithm="HS256")
    resp = make_response("Logged in")
    # Vulnerability: cookie without Secure / HttpOnly / SameSite flags
    resp.set_cookie("session", token)
    return resp


@app.route("/profile")
def profile():
    token = request.cookies.get("session", "")
    # Vulnerability: JWT signature verification disabled
    payload = jwt.decode(token, options={"verify_signature": False})
    return "Role: " + payload.get("role", "")


@app.route("/greet")
def greet():
    # Vulnerability: server-side template injection (SSTI)
    name = request.args.get("name", "guest")
    return render_template_string("Hello " + name)


@app.route("/redirect")
def open_redirect():
    # Vulnerability: open redirect
    return redirect(request.args.get("next", "/"))


@app.route("/upload-xml", methods=["POST"])
def upload_xml():
    # Vulnerability: XML External Entity (XXE) injection
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(request.data, parser)
    return root.tag


@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    # Vulnerability: untrusted XML parsed with stdlib parser (billion laughs)
    return ET.fromstring(request.data).tag


@app.route("/error")
def error():
    try:
        1 / 0
    except Exception as e:
        # Vulnerability: detailed error / stack info leaked to client
        return "Internal error: " + repr(e), 500


@app.after_request
def add_cors(resp):
    # Vulnerability: overly permissive CORS with credentials
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
