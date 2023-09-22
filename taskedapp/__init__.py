from flask import Flask
from .main.routes import main
from .extensions import mongo


def create_app():
    app = Flask(__name__, template_folder='docs')
    app.secret_key = "secret_key"

    app.config["MONGO_URI"] = "mongodb://localhost:27017"

    mongo.init_app(app)

    app.register_blueprint(main)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
