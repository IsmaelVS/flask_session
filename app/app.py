# coding: utf-8
"""Formulário web utilizando Flask e WTForms."""

import datetime
from functools import wraps

import jwt
from flask import Flask, jsonify, make_response, render_template, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import Form, PasswordField, StringField, SubmitField

app = Flask(__name__)

app.config['SECRET_KEY'] = 'teste'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)


class Usuario(db.Model):
    """Classe para criação da tabela usuário no banco."""

    __tablename__ = 'usuario'

    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, username, password, admin):
        db.create_all()
        self.username = username
        self.password = password
        self.admin = admin

    def __repr__(self):
        return """
        Usuario(username={}, password={}, admin={})""".format(
            self.username, self.password, self.admin)


class Login(Form):
    """Classe para montar o formulário."""

    login = StringField('Username')
    password = PasswordField('Password')
    btn = SubmitField('Logar')


class Cadastro(Form):
    """Classe para montar o formulário de cadastro."""

    login = StringField('Username')
    password = PasswordField('Password')
    btn = SubmitField('Cadastrar')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'token' in request.headers:
            token = request.headers['token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Usuario.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/login')
def login():
    """Rota inicial, exibe o template do formulário."""
    return render_template('login.html', form=Login())


@app.route('/check_login', methods=['POST'])
def check_login():
    """Rota para validar dados do formulário."""
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {
            'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = Usuario.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {
            'WWW-Authenticate': 'Basic realm="Login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
         'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
         app.config['SECRET_KEY'])

        # request.headers['token'] = token
        return jsonify({'token': token.decode('UTF-8')})
        # return url_for('logado')

    return make_response('Could not verify', 401, {
        'WWW-Authenticate': 'Basic realm="Login required!"'})


def validate_login(user, senha):
    """Função de validação dos dados do formulário."""
    return db.session.query(Usuario).filter_by(
        username=user, password=senha).first()


@app.route('/')
def home():
    """Rota inicial, com formulário para cadastro."""
    return render_template('cadastro.html', form=Cadastro())


@app.route('/checar_cadastro', methods=['POST'])
def checar_cadastro():
    """Rota para checar cadastro."""
    username = request.form['login']
    hashed_password = generate_password_hash(
        request.form['password'], method='sha256')
    user = Usuario(
        username=username,
        password=hashed_password,
        admin=True)
    db.session.add(user)
    db.session.commit()
    return render_template('login.html', form=Login())


@app.route('/logado')
@token_required
def logado(current_user):
    """Rota inicial após a realização de login."""
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    return 'Logado com sucesso!!'


if __name__ == '__main__':
    app.run(debug=True)
