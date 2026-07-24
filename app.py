"""
app.py — Flask Web Server for Secure Vault
============================================
REST API backend that wraps the existing encryption engine (vault.py),
authentication module (user.py), and password generator (generator.py)
into a clean set of HTTP endpoints consumed by a single-page frontend.

This is a single-user, local-only application. The master password is
held in server memory for the duration of the authenticated session and
is never written to disk or sent back to the client.
"""

import os
import sys
import json
from functools import wraps
from datetime import datetime

from flask import Flask, request, jsonify, render_template

# Ensure project root is on the import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vault import Vault
from user import User, MASTER_KEY_FILE, DATA_DIR
from generator import PasswordGenerator

# ====================================================================== #
#  Application Setup
# ====================================================================== #

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Single-user in-memory auth state — never persisted or sent to client
_auth = {"master_password": None}

vault_instance = Vault()
user_instance = User()


# ====================================================================== #
#  Auth Decorator
# ====================================================================== #

def require_auth(f):
    """Decorator: reject requests when no master password is authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _auth["master_password"] is None:
            return jsonify({"success": False, "message": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated


# ====================================================================== #
#  Helper Utilities
# ====================================================================== #

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_entries() -> list[dict]:
    """Load and decrypt all credential entries from the vault."""
    try:
        return vault_instance.load(_auth["master_password"])
    except Exception:
        return []


def _save_entries(entries: list[dict]) -> None:
    """Encrypt and persist credential entries to the vault file."""
    vault_instance.save(entries, _auth["master_password"])


# ====================================================================== #
#  Page Route
# ====================================================================== #

@app.route("/")
def index():
    """Serve the single-page application."""
    return render_template("index.html")


# ====================================================================== #
#  Auth Endpoints
# ====================================================================== #

@app.route("/api/status", methods=["GET"])
def api_status():
    """Return whether first-time setup is complete and login state."""
    return jsonify({
        "setup_complete": user_instance.is_setup_complete(),
        "logged_in": _auth["master_password"] is not None,
    })


@app.route("/api/setup", methods=["POST"])
def api_setup():
    """First-time master password creation."""
    if user_instance.is_setup_complete():
        return jsonify({"success": False, "message": "Setup already completed"}), 400

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    confirm = data.get("confirm", "")

    if password != confirm:
        return jsonify({"success": False, "message": "Passwords do not match"}), 400

    is_valid, issues = User.validate_password_strength(password)
    if not is_valid:
        return jsonify({"success": False, "issues": issues}), 400

    # Hash and persist master password
    salt = os.urandom(16)
    hashed = user_instance._hash_password(password, salt)
    key_data = {"salt": salt.hex(), "hash": hashed}

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(MASTER_KEY_FILE, "w") as f:
        json.dump(key_data, f, indent=2)

    # Initialize empty vault
    _auth["master_password"] = password
    vault_instance.save([], password)

    return jsonify({"success": True})


@app.route("/api/login", methods=["POST"])
def api_login():
    """Authenticate with the master password."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not user_instance.is_setup_complete():
        return jsonify({"success": False, "message": "Setup not complete"}), 400

    if user_instance.verify_password(password):
        _auth["master_password"] = password
        return jsonify({"success": True})

    return jsonify({"success": False, "message": "Incorrect master password"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Clear the authenticated session."""
    _auth["master_password"] = None
    return jsonify({"success": True})


# ====================================================================== #
#  Credential Endpoints
# ====================================================================== #

@app.route("/api/credentials", methods=["GET"])
@require_auth
def api_get_credentials():
    """Return all stored credentials (decrypted)."""
    entries = _load_entries()
    # Attach an index-based ID for frontend reference
    for i, entry in enumerate(entries):
        entry["id"] = i
    return jsonify({"success": True, "credentials": entries})


@app.route("/api/credentials", methods=["POST"])
@require_auth
def api_add_credential():
    """Add a new credential to the vault."""
    data = request.get_json(silent=True) or {}
    service = data.get("service", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not service:
        return jsonify({"success": False, "message": "Service name is required"}), 400
    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400
    if not password:
        return jsonify({"success": False, "message": "Password is required"}), 400

    entries = _load_entries()

    # Check for duplicates
    for entry in entries:
        if entry["service"].lower() == service.lower() and entry["username"].lower() == username.lower():
            return jsonify({
                "success": False,
                "message": f"A credential for '{service}' with username '{username}' already exists",
                "duplicate": True,
            }), 409

    new_entry = {
        "service": service,
        "username": username,
        "password": password,
        "created_at": _now(),
        "updated_at": _now(),
    }
    entries.append(new_entry)
    _save_entries(entries)

    return jsonify({"success": True, "message": f"Credential for '{service}' saved"})


@app.route("/api/credentials/<int:cred_id>", methods=["PUT"])
@require_auth
def api_update_credential(cred_id: int):
    """Update an existing credential by its index ID."""
    entries = _load_entries()

    if cred_id < 0 or cred_id >= len(entries):
        return jsonify({"success": False, "message": "Credential not found"}), 404

    data = request.get_json(silent=True) or {}
    target = entries[cred_id]

    if "service" in data and data["service"].strip():
        target["service"] = data["service"].strip()
    if "username" in data and data["username"].strip():
        target["username"] = data["username"].strip()
    if "password" in data and data["password"].strip():
        target["password"] = data["password"].strip()

    target["updated_at"] = _now()
    _save_entries(entries)

    return jsonify({"success": True, "message": f"Credential for '{target['service']}' updated"})


@app.route("/api/credentials/<int:cred_id>", methods=["DELETE"])
@require_auth
def api_delete_credential(cred_id: int):
    """Delete a credential by its index ID."""
    entries = _load_entries()

    if cred_id < 0 or cred_id >= len(entries):
        return jsonify({"success": False, "message": "Credential not found"}), 404

    removed = entries.pop(cred_id)
    _save_entries(entries)

    return jsonify({"success": True, "message": f"Credential for '{removed['service']}' deleted"})


@app.route("/api/search", methods=["GET"])
@require_auth
def api_search():
    """Search credentials by service name or username (case-insensitive)."""
    query = request.args.get("q", "").strip().lower()
    if not query:
        return jsonify({"success": False, "message": "Search query is required"}), 400

    entries = _load_entries()
    results = []
    for i, entry in enumerate(entries):
        if query in entry["service"].lower() or query in entry["username"].lower():
            entry["id"] = i
            results.append(entry)

    return jsonify({"success": True, "credentials": results, "query": query})


# ====================================================================== #
#  Password Generator Endpoint
# ====================================================================== #

@app.route("/api/generate", methods=["POST"])
@require_auth
def api_generate():
    """Generate a secure random password with configurable options."""
    data = request.get_json(silent=True) or {}

    length = data.get("length", 16)
    use_uppercase = data.get("uppercase", True)
    use_lowercase = data.get("lowercase", True)
    use_digits = data.get("digits", True)
    use_symbols = data.get("symbols", True)

    try:
        length = int(length)
        length = max(4, min(128, length))
    except (ValueError, TypeError):
        length = 16

    try:
        password = PasswordGenerator.generate(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_symbols=use_symbols,
        )
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    rating, score, _ = PasswordGenerator.evaluate_strength(password)
    # Strip emoji from rating for clean JSON
    rating_clean = rating.split(" ")[0] if " " in rating else rating

    return jsonify({
        "success": True,
        "password": password,
        "strength": {"rating": rating_clean, "score": score},
    })


# ====================================================================== #
#  Master Password Change Endpoint
# ====================================================================== #

@app.route("/api/change-password", methods=["POST"])
@require_auth
def api_change_password():
    """Change the master password and re-encrypt the vault."""
    data = request.get_json(silent=True) or {}
    current = data.get("current_password", "")
    new_password = data.get("new_password", "")
    confirm = data.get("confirm_password", "")

    # Verify current password
    if not user_instance.verify_password(current):
        return jsonify({"success": False, "message": "Current password is incorrect"}), 401

    if new_password != confirm:
        return jsonify({"success": False, "message": "New passwords do not match"}), 400

    is_valid, issues = User.validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"success": False, "issues": issues}), 400

    # Re-encrypt vault with new password
    try:
        entries = vault_instance.load(current)
        vault_instance.save(entries, new_password)
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to re-encrypt vault: {e}"}), 500

    # Update master password hash
    salt = os.urandom(16)
    hashed = user_instance._hash_password(new_password, salt)
    key_data = {"salt": salt.hex(), "hash": hashed}

    with open(MASTER_KEY_FILE, "w") as f:
        json.dump(key_data, f, indent=2)

    _auth["master_password"] = new_password

    return jsonify({"success": True, "message": "Master password changed successfully"})


# ====================================================================== #
#  Password Strength Check (for live UI feedback)
# ====================================================================== #

@app.route("/api/check-strength", methods=["POST"])
def api_check_strength():
    """Evaluate the strength of a given password (no auth required for setup)."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"score": 0, "rating": "Empty"})

    rating, score, _ = PasswordGenerator.evaluate_strength(password)
    rating_clean = rating.split(" ")[0] if " " in rating else rating

    is_valid, issues = User.validate_password_strength(password)

    return jsonify({
        "score": score,
        "rating": rating_clean,
        "valid": is_valid,
        "issues": issues,
    })


# ====================================================================== #
#  Entry Point
# ====================================================================== #

if __name__ == "__main__":
    print("\n  [*] Secure Vault - Web Server")
    print("  ---------------------------------")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(debug=True, host="127.0.0.1", port=5000)

