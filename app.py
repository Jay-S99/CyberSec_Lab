import os

from flask import Flask, jsonify

from config import Config


def create_app(config_class=Config):
    application = Flask(__name__, instance_relative_config=True)
    application.config.from_object(config_class)
    os.makedirs(application.instance_path, exist_ok=True)

    @application.get("/health")
    def health():
        return jsonify(status="ok")

    return application


app = create_app()


if __name__ == "__main__":
    app.run()
