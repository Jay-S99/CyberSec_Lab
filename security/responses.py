from flask import jsonify, request


def wants_json_response():
    return (
        request.path == "/api"
        or request.path.startswith("/api/")
        or request.is_json
        or request.accept_mimetypes.best_match(
            ["text/html", "application/json"]
        ) == "application/json"
    )


def authentication_required_response():
    return jsonify(error="authentication_required"), 401
