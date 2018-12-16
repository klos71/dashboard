from flask import Flask, request, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin
import flask_login
import subprocess
import spur

users = {'foo@bar.tld': {'password': 'secret'}, 'test@test.test': {'password': 'secret'}}

login_manager = LoginManager()

app = Flask(__name__)

login_manager.init_app(app)

app.secret_key = 'super secret string'


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if email not in users:
        return

    user = User()
    user.id = email

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    user.is_authenticated = request.form['password'] == users[email]['password']

    return user


@app.route('/')
def hello_world():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")

    email = request.form['email']
    if request.form['password'] == users[email]['password']:
        user = User()
        user.id = email
        flask_login.login_user(user)
        return redirect(url_for('protected'))

    return 'Bad login'


@app.route('/protected', methods=['GET', 'POST'])
@flask_login.login_required
def protected():
    if request.method == 'GET':
        return render_template("user.html")

    if request.method == "POST":
        shell = spur.SshShell(hostname="192.168.33.10", username="vagrant", password="vagrant")
        result = shell.run(["ls"])
        return render_template("user.html", output=result.output)


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    email = request.form['email']
    password = request.form['password']
    user = User()
    user.id = email
    user.password = password


@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'


if __name__ == '__main__':
    app.run()
