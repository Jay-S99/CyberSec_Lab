import os

from flask import Flask, jsonify

from auth.login import init_app as init_login
from auth.temp_passwords import init_app as init_provisioning
from config import Config
from database import init_app as init_database
from modules.admin import bp as admin_blueprint
from modules.dossiers import bp as dossiers_blueprint
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
    application.register_blueprint(admin_blueprint)
    application.register_blueprint(dossiers_blueprint)
    init_errors(application)

    @application.context_processor
    def administration_navigation():
        from security.permissions import has_permission

        return {
            "can_manage_users": has_permission("users.manage"),
            "can_manage_security": has_permission("security.manage"),
        }

    @application.get("/health")
    def health():
        return jsonify(status="ok")

    return application


app = create_app()


if __name__ == "__main__":
    app.run()
