import os
from flask import Flask, request, jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@"
    f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
)

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# Login View
login_manager.login_view = "login"

# Recuperar a sessão do usuário
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()
        hashed_password_check_ok = bcrypt.checkpw(str.encode(password), str.encode(user.password))

        if user and hashed_password_check_ok:
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso"}), 200

    return jsonify({ "message": "Credenciais inválidas" }), 400

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role="user")
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"}), 201

    return jsonify({"message": "Dados inválidos"}), 400

@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return jsonify({ "username": user.username }), 200
    
    return user_not_found()

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    if id_user != current_user.id and current_user.role=='user':
        return jsonify({"message": "Operação não permitida"}), 403

    data = request.json
    password = data.get("password")
    user = User.query.get(id_user)

    if user and password:
        new_password_hashed = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user.password = new_password_hashed
        db.session.commit()
        return jsonify({"message": f"Usuário {user.username} atualizado com sucesso"}), 200

    return user_not_found()

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    if current_user.role != 'admin':
        return jsonify({"message": "Operação não permitida"}), 403
    
    if id_user == current_user.id:
        return jsonify({"message": "Exclusão não permitida"}), 403

    user = User.query.get(id_user)

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {user.username} apagado com sucesso"}), 200

    return user_not_found()

@app.route("/hello-world", methods=["GET"])
def hello_world():
    return "Hello World"

def user_not_found():
    return jsonify({"message": "Usuário não encontrado"}), 404


if __name__ == '__main__':
    app.run(debug=True)