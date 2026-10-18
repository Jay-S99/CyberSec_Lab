import os

from flask import Flask, jsonify

from auth.login import init_app as init_login
from auth.temp_passwords import init_app as init_provisioning
from config import Config
from database import init_app as init_database
from seed import init_app as init_seed


def create_app(config_class=Config):
    application = Flask(__name__, instance_relative_config=True)
    application.config.from_object(config_class)
    os.makedirs(application.instance_path, exist_ok=True)
    init_database(application)
    init_seed(application)
    init_login(application)
    init_provisioning(application)

    @application.get("/health")
    def health():
        return jsonify(status="ok")

    return application


app = create_app()


if __name__ == "__main__":
    app.run()
