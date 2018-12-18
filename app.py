from flask import Flask, request, redirect, url_for, render_template, g
from flask_login import LoginManager, UserMixin
import flask_login, spur, sqlite3, flask_bcrypt


login_manager = LoginManager()

app = Flask(__name__)

login_manager.init_app(app)

app.secret_key = 'super secret string'

bcrypt = flask_bcrypt.Bcrypt(app)

DATABASE = "database.db"


class User(UserMixin):
    pass


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@login_manager.user_loader
def user_loader(email):

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    temp = []
    for user in query_db('select * from dashboard_users'):
        temp.append(user)
    if email not in temp:
        return

    user = User()
    user.id = email

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    temp = query_db('SELECT password FROM dashboard_users WHERE email = ?', [email], one=True)
    user.is_authenticated = request.form['password'] == str(temp).split("'")[1]

    return user


@app.route('/')
def hello_world():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")

    email = request.form['email']
    temp = query_db('SELECT password FROM dashboard_users WHERE email = ?', [email], one=True)

    if bcrypt.check_password_hash(str(temp).split("'")[1], request.form['password']):
        user = User()
        user.id = email
        flask_login.login_user(user)
        return redirect(url_for('protected'))
    msg = "Wrong username/password"
    return render_template("login.html", msg=msg)


@app.route('/protected', methods=['GET', 'POST'])
@flask_login.login_required
def protected():
    if request.method == 'GET':
        return render_template("user.html")

    if request.method == "POST":
        shell = spur.SshShell(hostname="192.168.33.10", username="vagrant", password="vagrant")
        result = shell.run(["ls"])
        return render_template("user.html", output=result.output)

@app.route('/remove_acc', methods=['POST'])
@flask_login.login_required
def removeAcc():
    if request.method == "POST":
        conn = sqlite3.connect("database.db")
        name = str(flask_login.current_user.id).split("'")[1]
        try:
            conn.execute("DELETE FROM dashboard_users where email = ?", [name])
            conn.commit()
            msg = "User was Deleted"
            flask_login.login_user()
            return render_template("register.html", msg=msg)
        except:
            msg = "ERROR!" , " ", name
            conn.rollback()
        finally:
            conn.close()
            return render_template("register.html", msg=msg)

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return render_template("index.html")

@app.route('/settings')
@flask_login.login_required
def settings():
    return render_template("settings.html")

@app.route('/add_machine', methods=["POST"])
@flask_login.login_required
def addMachine():
    ip = request.form["ipAddr"]
    username = request.form["username"]
    password = request.form["password"]
    email = flask_login.current_user.id
    conn = sqlite3.connect("database.db")
    ID = conn.execute("SELECT ID FROM dashboard_users WHERE email= ?", [email])
    try:
        conn.execute("INSERT INTO machines (IP, username, password, owner) VALUES (?,?,?,?)", (ip,username,password,ID))
        conn.commit()
        msg = "Succses"
    except:
        conn.rollback()
        msg = "FAIL"
    finally:
        conn.close()
        return render_template("user.html",output=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        for user_email in query_db("SELECT email FROM dashboard_users"):
            if str(email).split("'")[0] == str(user_email["email"]).split("'")[1]:
                msg = "Username already exists"
                return render_template("register.html", msg=msg)
        password = request.form["password"]
        conn = sqlite3.connect('database.db')
        password = bcrypt.generate_password_hash(password)
        try:
            conn.execute('INSERT INTO dashboard_users (username, email, password) VALUES (?, ?, ?)',(username, email, password))
            conn.commit()
            msg = "Sucsesfully registered"
            return render_template("login.html", msg=msg)
        except:
            msg = "ERROR!"
            conn.rollback()
        finally:
            conn.close()
            return render_template("login.html", msg=msg)

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'


if __name__ == '__main__':
    app.run()
