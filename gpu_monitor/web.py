"""Flask application factory and HTTP routes."""

from pathlib import Path
import os
import secrets

from flask import Blueprint, Flask, current_app, g, jsonify, redirect, render_template, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from .auth import AuthStore, CHALLENGE_COOKIE, CHALLENGE_TTL, COOKIE_NAME, KEY_ID_PATTERN, SESSION_TTL

from .access.service import (
    build_access_matrix,
    configure_access_pairs,
    configure_selected_access,
    delete_user_access,
    delete_user_keys,
    detect_server_users,
    list_user_keys,
    normalize_name_list,
    revoke_access_pairs,
    serialize_user_operations,
)
from .config import get_configured_servers, get_monitoring_settings, load_config
from .gpu.state import gpu_state
from .storage import storage_state
from .user_store import (
    MAX_SSH_KEY_INPUT_SIZE,
    add_user_key,
    find_ssh_key_matches,
    import_user_keys,
    normalize_ssh_key,
)


bp = Blueprint("gpu_monitor", __name__)


@bp.before_request
def require_login():
    g.script_nonce = secrets.token_urlsafe(24)
    if request.endpoint in {"gpu_monitor.login_page", "gpu_monitor.login_asset",
                            "gpu_monitor.auth_challenge", "gpu_monitor.auth_verify"}:
        return None
    g.username = current_app.extensions["monitor_auth"].user(request.cookies.get(COOKIE_NAME))
    if not g.username:
        if request.path.startswith("/api/"):
            return jsonify({"error": "login_required"}), 401
        return redirect("/login")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not same_origin_request():
        return jsonify({"error": "invalid_origin"}), 403


def same_origin_request():
    origin = request.headers.get("Origin")
    return request.headers.get("X-Monitor-Request") == "1" and (
        origin is None or origin == request.host_url.rstrip("/"))


@bp.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.endpoint == "gpu_monitor.login_asset":
        policy = "default-src 'none'; script-src 'self'; connect-src 'none'"
    else:
        nonce = getattr(g, "script_nonce", "")
        policy = (f"default-src 'none'; script-src 'self' 'nonce-{nonce}'; "
                  "style-src 'self' 'unsafe-inline'; connect-src 'self'; worker-src 'self'; "
                  "img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    response.headers["Content-Security-Policy"] = policy
    return response


@bp.route("/login")
def login_page():
    return render_template("login.html")


@bp.route("/login-assets/<filename>")
def login_asset(filename):
    if filename not in {"login.js", "login-worker.js", "login.css", "ui.js", "monitor.css"}:
        return "", 404
    return send_from_directory(Path(__file__).resolve().parent.parent / "static", filename)


def auth_payload(fields):
    if not same_origin_request():
        return None, (jsonify({"error": "invalid_origin"}), 403)
    if request.content_length is None or request.content_length > 16384:
        return None, (jsonify({"error": "invalid_request"}), 400)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != set(fields) or any(
        not isinstance(payload[field], str) or len(payload[field]) > 8192 for field in fields
    ):
        return None, (jsonify({"error": "invalid_request"}), 400)
    if not current_app.extensions["monitor_auth"].throttle(request.remote_addr):
        return None, (jsonify({"error": "too_many_attempts"}), 429)
    return payload, None


@bp.route("/api/auth/challenge", methods=["POST"])
def auth_challenge():
    payload, error = auth_payload(["key_id"])
    if error:
        return error
    if not KEY_ID_PATTERN.fullmatch(payload["key_id"]):
        return jsonify({"error": "invalid_request"}), 400
    result = current_app.extensions["monitor_auth"].challenge(payload["key_id"], request.host_url.rstrip("/"))
    if not result:
        return jsonify({"error": "key_not_registered"}), 403
    challenge, binding = result
    response = jsonify(challenge)
    response.set_cookie(CHALLENGE_COOKIE, binding, max_age=CHALLENGE_TTL,
                        secure=True, httponly=True, samesite="Strict", path="/api/auth")
    return response


@bp.route("/api/auth/verify", methods=["POST"])
def auth_verify():
    payload, error = auth_payload(["challenge_id", "signature"])
    if error:
        return error
    result = current_app.extensions["monitor_auth"].login(
        payload["challenge_id"], payload["signature"], request.cookies.get(CHALLENGE_COOKIE))
    if not result:
        return jsonify({"error": "invalid_signature"}), 403
    token, username = result
    response = jsonify({"username": username})
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL,
                        secure=True, httponly=True, samesite="Strict")
    response.delete_cookie(CHALLENGE_COOKIE, path="/api/auth", secure=True, httponly=True, samesite="Strict")
    return response


@bp.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    current_app.extensions["monitor_auth"].logout(request.cookies.get(COOKIE_NAME, ""))
    response = jsonify({"ok": True})
    response.delete_cookie(COOKIE_NAME, secure=True, httponly=True, samesite="Strict")
    return response


def is_admin_authorized():
    """Validate the per-request administrator token."""
    expected_token = load_config().get("admin_token", "")
    if not expected_token:
        return False
    supplied_token = request.headers.get("X-Admin-Token", "")
    return supplied_token == expected_token


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/api/gpu")
def get_gpu():
    return jsonify(gpu_state.get_cached_data())


@bp.route("/api/storage")
def get_storage():
    return jsonify(storage_state.get_cached_data())


@bp.route("/api/servers")
def get_servers():
    servers = [{"name": server["name"]} for server in get_configured_servers()]
    settings = get_monitoring_settings()
    return jsonify(
        {
            "servers": servers,
            "refresh_interval": settings["refresh_interval"],
        }
    )


def get_query_name_list(name):
    values = request.args.getlist(name)
    if not values:
        return None
    return normalize_name_list(values)


@bp.route("/api/access-matrix", methods=["GET", "POST"])
def get_access_matrix():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        server_names = payload.get("servers")
        usernames = payload.get("users")
    else:
        server_names = get_query_name_list("servers")
        usernames = get_query_name_list("users")

    result, status_code = build_access_matrix(server_names, usernames)
    return jsonify(result), status_code


@bp.route("/api/check-ssh-key", methods=["POST"])
def check_ssh_key():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    ssh_key = payload.get("ssh_key", "")
    if not isinstance(ssh_key, str) or not normalize_ssh_key(ssh_key):
        return jsonify({"error": "ssh_key_required"}), 400
    if len(ssh_key) > MAX_SSH_KEY_INPUT_SIZE:
        return jsonify({"error": "invalid_ssh_key"}), 400

    result = find_ssh_key_matches(ssh_key)
    if result is None:
        return jsonify({"error": "invalid_ssh_key"}), 400
    return jsonify(result)


@bp.route("/api/users", methods=["POST"])
def add_user():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    with serialize_user_operations([username]):
        result, status_code = add_user_key(
            username,
            payload.get("ssh_key", ""),
        )
    return jsonify(result), status_code


@bp.route("/api/detect-users", methods=["POST"])
def detect_users():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    result, status_code = detect_server_users(payload.get("servers"))
    return jsonify(result), status_code


@bp.route("/api/import-users", methods=["POST"])
def import_users():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    items = payload.get("items")
    usernames = []
    if isinstance(items, list):
        usernames = [
            item.get("username")
            for item in items
            if isinstance(item, dict) and isinstance(item.get("username"), str)
        ]
    with serialize_user_operations(usernames):
        result, status_code = import_user_keys(items)
    return jsonify(result), status_code


@bp.route("/api/users/<username>", methods=["DELETE"])
def delete_user(username):
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    result, status_code = delete_user_access(username, payload)
    return jsonify(result), status_code


@bp.route("/api/users/<username>/keys", methods=["GET", "DELETE"])
def user_keys(username):
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    if request.method == "GET":
        result, status_code = list_user_keys(username)
    else:
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        result, status_code = delete_user_keys(username, payload)
    return jsonify(result), status_code


@bp.route("/api/configure-access", methods=["POST"])
def configure_access():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    pairs = payload.get("pairs")
    if pairs is not None:
        if not isinstance(pairs, list) or not pairs:
            return jsonify({"error": "select_at_least_one_access_pair"}), 400
        result, status_code = configure_access_pairs(pairs)
        return jsonify(result), status_code

    server_names = payload.get("servers", [])
    usernames = payload.get("users", [])
    if not isinstance(server_names, list) or not isinstance(usernames, list):
        return jsonify({"error": "servers_and_users_must_be_lists"}), 400

    server_names = [name for name in server_names if isinstance(name, str)]
    usernames = [username for username in usernames if isinstance(username, str)]
    if not server_names or not usernames:
        return jsonify({"error": "select_at_least_one_server_and_user"}), 400

    result, status_code = configure_selected_access(server_names, usernames)
    return jsonify(result), status_code


@bp.route("/api/revoke-access", methods=["POST"])
def revoke_access():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return jsonify({"error": "request_body_must_be_an_object"}), 400
    pairs = payload.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        return jsonify({"error": "select_at_least_one_access_pair"}), 400

    result, status_code = revoke_access_pairs(pairs)
    return jsonify(result), status_code


def create_app(test_config=None):
    """Create a Flask app without starting background collectors."""
    template_folder = Path(__file__).resolve().parent.parent / "templates"
    app = Flask(
        __name__,
        template_folder=str(template_folder),
        static_folder=None,
    )
    app.config["AUTH_DATABASE"] = os.environ.get(
        "GPU_MONITOR_AUTH_DATABASE", str(template_folder.parent / "auth.sqlite3"))
    if test_config:
        app.config.update(test_config)
    if os.environ.get("GPU_MONITOR_TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
    app.extensions["monitor_auth"] = AuthStore(app.config["AUTH_DATABASE"])
    app.register_blueprint(bp)
    return app
