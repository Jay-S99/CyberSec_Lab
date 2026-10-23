import os

from flask import Flask, g, jsonify

from auth.login import init_app as init_login
from auth.temp_passwords import init_app as init_provisioning
from config import Config
from database import get_db, init_app as init_database
from localization import init_app as init_localization
from modules.admin import bp as admin_blueprint
from modules.dossiers import bp as dossiers_blueprint
from modules.incidents import bp as incidents_blueprint
from security.errors import init_app as init_errors
from seed import init_app as init_seed


def create_app(config_class=Config):
    application = Flask(__name__, instance_relative_config=True)
    application.config.from_object(config_class)
    if application.config.get("ENVIRONMENT") == "production":
        application.config["AUTH_COOKIE_SECURE"] = True
    os.makedirs(application.instance_path, exist_ok=True)
    init_database(application)
    init_seed(application)
    init_login(application)
    init_provisioning(application)
    init_localization(application)
    application.register_blueprint(admin_blueprint)
    application.register_blueprint(dossiers_blueprint)
    application.register_blueprint(incidents_blueprint)
    init_errors(application)

    @application.context_processor
    def administration_navigation():
        from security.permissions import has_permission

        role_name = None
        if g.get("user") is not None:
            role = get_db().execute(
                "SELECT name FROM roles WHERE id = ?", (g.user["role_id"],)
            ).fetchone()
            role_name = role["name"] if role is not None else None

        dossier_permissions = (
            "dossiers.read_declassified",
            "dossiers.read_classified",
            "dossiers.read_doom_level",
            "dossiers.read_own_drafts",
        )
        return {
            "current_role_name": role_name,
            "can_browse_dossiers": any(
                has_permission(permission) for permission in dossier_permissions
            ),
            "can_manage_users": has_permission("users.manage"),
            "can_manage_security": has_permission("security.manage"),
            "can_create_dossier": has_permission("dossiers.create"),
            "can_create_incident": has_permission("incidents.create"),
            "can_review_incidents": has_permission("incidents.read_submitted"),
            "can_review_dossiers": has_permission("dossiers.review"),
        }

    @application.get("/health")
    def health():
        return jsonify(status="ok")

    return application


app = create_app()


if __name__ == "__main__":
    app.run()
