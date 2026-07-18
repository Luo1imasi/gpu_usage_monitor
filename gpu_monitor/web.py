"""Flask application factory and HTTP routes."""

from pathlib import Path

from flask import Blueprint, Flask, jsonify, render_template, request

from .access.service import (
    build_access_matrix,
    configure_access_pairs,
    configure_selected_access,
    delete_user_access,
    delete_user_keys,
    detect_server_users,
    list_user_keys,
    normalize_name_list,
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
    result, status_code = add_user_key(
        payload.get("username", ""),
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
    result, status_code = import_user_keys(payload.get("items"))
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


def create_app():
    """Create a Flask app without starting background collectors."""
    template_folder = Path(__file__).resolve().parent.parent / "templates"
    app = Flask(
        __name__,
        template_folder=str(template_folder),
        static_folder=None,
    )
    app.register_blueprint(bp)
    return app
