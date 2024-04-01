from flask import Flask, jsonify, request, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from psutil import users

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)
app.secret_key = "secret_key"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    # write code ------->
    phoneNumber = db.Column(db.String(20), nullable=False, unique=True)
    role = db.Column(db.String(20), nullable=True, default="Unassigned")

    def __init__(self, email, password, name, phoneNumber, role):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        self.phoneNumber = phoneNumber
        self.role = role

    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password.encode("utf-8"))


with app.app_context():
    db.create_all()


@app.route("/")
def root():
    return render_template("root.html")


@app.route("/auth")
def index():
    return render_template("index.html")


@app.route("/auth/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        phoneNumber = request.form["phoneNumber"]
        role = request.form["role"]

        if not name or not email or not password or not phoneNumber or not role:
            return render_template(
                "register.html", error="Please fill in all the fields."
            )

        new_user = User(
            name=name,
            email=email,
            password=password,
            phoneNumber=phoneNumber,
            role=role,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect("/auth/login")

    return render_template("register.html")


@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["email"] = user.email
            return redirect("/auth/dashboard")
        else:
            return render_template("login.html", error="Invalid user")

    return render_template("login.html")


@app.route("/auth/dashboard")
def dashboard():
    if session["email"]:
        user = User.query.filter_by(email=session["email"]).first()
        return render_template("dashboard.html", user=user)

    return redirect("/auth/login")


@app.route("/auth/logout")
def logout():
    session.pop("email", None)
    return redirect("/auth/login")


@app.route("/auth/reset-password/initiate", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        old_password = request.form["prev_password"]
        new_password = request.form["new_password"]

        user = User.query.filter_by(email=email).first()

        if user:
            if user.check_password(old_password):

                user.password = bcrypt.hashpw(
                    new_password.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")
                db.session.commit()
                return redirect("/auth")
            else:
                return render_template(
                    "reset-password.html", error="Old password does not match"
                )
        else:
            return render_template("reset-password.html", error="Invalid email")

    return render_template("reset-password.html")


@app.route("/users", methods=["GET"])
def list_users():
    if request.method == "GET":
        users = User.query.all()
        user_list = [
            {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "phoneNumber": user.phoneNumber,
                "role": user.role,
            }
            for user in users
        ]
        return jsonify({"users": user_list}), 200
    else:
        return jsonify({"error": "Unauthorized"}), 401


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    if request.method == "GET":
        user = User.query.get(user_id)
        if user:
            user_details = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "phoneNumber": user.phoneNumber,
                "role": user.role,
            }
            return jsonify(user_details), 200
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Unauthorized"}), 401


@app.route("/users", methods=["POST"])
def create_user():
    if request.method == "POST":
        user_data = request.json

        name = user_data.get("name")
        email = user_data.get("email")
        phoneNumber = user_data.get("phoneNumber")
        role = user_data.get("role")
        password = user_data.get("password")

        if not name or not email or not phoneNumber or not role or not password:
            return jsonify({"error": "Missing required fields"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already exists"}), 409

        new_user = User(
            name=name,
            email=email,
            phoneNumber=phoneNumber,
            role=role,
            password=password,
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User created successfully"}), 201

    return jsonify({"error": "Unauthorized"}), 401


@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    if request.method == "PUT":
        updated_data = request.json

        user = User.query.get(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        if user:
            if "name" in updated_data:
                user.name = updated_data["name"]
            if "email" in updated_data:
                user.email = updated_data["email"]
            if "phoneNumber" in updated_data:
                user.phoneNumber = updated_data["phoneNumber"]
            if "role" in updated_data:
                user.role = updated_data["role"]

            db.session.commit()

            return jsonify({"message": "User details updated successfully"}), 200
        else:
            return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"error": "Method Not Allowed"}), 405


@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if request.method == "DELETE":

        user = User.query.get(user_id)

        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    return jsonify({"error": "Method Not Allowed"}), 405


@app.route("/users/roles", methods=["GET"])
def list_roles():
    roles = User.query.with_entities(User.role).distinct().all()

    role_names = [role[0] for role in roles]

    return jsonify({"roles": role_names}), 200


@app.route("/users/<int:user_id>/roles", methods=["PUT"])
def update_user_roles(user_id):
    if request.method == "PUT":

        updated_data = request.json

        user = User.query.get(user_id)

        if user:
            roles_data = request.json.get("roles")

            user.role = updated_data["role"]

            db.session.commit()

            return jsonify({"message": "User roles updated successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    return jsonify({"error": "Method Not Allowed"}), 405


# #############################################################
# # Define your Role and Permission models here if not already defined

# # Example Role and Permission models:
# class Role(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(50), unique=True, nullable=False)
#     permissions = db.relationship('Permission', secondary='role_permissions')

# class Permission(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(50), unique=True, nullable=False)
#     description = db.Column(db.String(200), nullable=True)

# # Route for defining and managing roles
# @app.route('/rbac/roles', methods=['GET', 'POST'])
# def manage_roles():
#     if request.method == 'GET':
#         roles = Role.query.all()
#         role_list = [{'id': role.id, 'name': role.name} for role in roles]
#         return jsonify({'roles': role_list}), 200

#     elif request.method == 'POST':
#         role_data = request.json
#         name = role_data.get('name')
#         if not name:
#             return jsonify({'error': 'Role name is required'}), 400

#         role = Role.query.filter_by(name=name).first()
#         if role:
#             return jsonify({'error': 'Role already exists'}), 409

#         new_role = Role(name=name)
#         db.session.add(new_role)
#         db.session.commit()
#         return jsonify({'message': 'Role created successfully'}), 201

# # Route for defining and managing permissions
# @app.route('/rbac/permissions', methods=['GET', 'POST'])
# def manage_permissions():
#     if request.method == 'GET':
#         permissions = Permission.query.all()
#         permission_list = [{'id': perm.id, 'name': perm.name, 'description': perm.description} for perm in permissions]
#         return jsonify({'permissions': permission_list}), 200

#     elif request.method == 'POST':
#         permission_data = request.json
#         name = permission_data.get('name')
#         description = permission_data.get('description')
#         if not name:
#             return jsonify({'error': 'Permission name is required'}), 400

#         permission = Permission.query.filter_by(name=name).first()
#         if permission:
#             return jsonify({'error': 'Permission already exists'}), 409

#         new_permission = Permission(name=name, description=description)
#         db.session.add(new_permission)
#         db.session.commit()
#         return jsonify({'message': 'Permission created successfully'}), 201


if __name__ == "__main__":
    app.run(debug=True)




































# @app.route('/register',methods=['GET','POST'])
# def register():
#     if request.method == 'POST':
#         # handle request
#         name = request.form['name']
#         email = request.form['email']
#         password = request.form['password']
#         phoneNumber = request.form['phoneNumber']
#         role = request.form['role']

#         new_user = User(name=name,email=email,password=password,phoneNumber=phoneNumber,role=role)
#         # new_user = User(name=name,email=email,password=password,phoneNumber=phoneNumber)
#         # new_user = User(name=name,email=email,password=password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect('/login')


#     return render_template('register.html')


# @app.route('/auth/reset-password', methods=['POST'])
# def reset_password():
#     return redirect('/auth/login')
# if request.method == 'POST':
#     email = request.json.get('email')  # Assuming JSON payload with 'email' field

#     # Here you can implement your logic to initiate the password reset process,
#     # such as sending an email with a password reset link, generating a token, etc.

#     # Example logic (replace with your actual implementation):
#     # - Check if the email exists in your database
#     # - Generate a password reset token
#     # - Send an email to the user with the password reset link containing the token

#     # Placeholder response
#     return jsonify({'message': 'Password reset initiated for email: {}'.format(email)}), 200

# return jsonify({'error': 'Method Not Allowed'}), 405


######################################
# @app.route('/auth/reset-password/initiate', methods=['GET', 'POST'])
# def reset_password():
#     if request.method == 'POST':
#         email = request.form['email']
#         new_password = request.form['new_password']

#         # Find the user by email
#         user = next((user for user in users if user["email"] == email), None)

#         if user:
#             # Update the user's password with the new password
#             user["password"] = new_password
#             return redirect('/auth/login')  # Redirect to login page after resetting password
#         else:
#             return render_template('reset-password.html', error='Invalid email')

#     return render_template('reset-password.html')


# @app.route('/auth/reset-password/initiate', methods=['GET', 'POST'])
# def reset_password():
#     if request.method == 'POST':
#         email = request.form['email']
#         new_password = request.form['new_password']

#         # Find the user by email
#         user = User.query.filter_by(email=email).first()

#         if user:
#             # Update the user's password with the new password

#             user.password = new_password
#             db.session.commit()  # Commit the changes to the database
#             return redirect('/auth')  # Redirect to login page after resetting password
#         else:
#             return render_template('reset-password.html', error='Invalid email')

#     return render_template('reset-password.html')


# @app.route('/auth/reset-password/initiate', methods=['POST'])
# def initiate_reset_password():
#     if request.method == 'POST':
#         email = request.json.get('email')  # Assuming JSON payload with 'email' field

#         # Here you can implement your logic to initiate the password reset process,
#         # such as sending an email with a password reset link, generating a token, etc.

#         # Example logic (replace with your actual implementation):
#         # - Check if the email exists in your database
#         # - Generate a password reset token
#         # - Send an email to the user with the password reset link containing the token

#         # Placeholder response
#         return jsonify({'message': 'Password reset initiated for email: {}'.format(email)}), 200

#     return jsonify({'error': 'Method Not Allowed'}), 405
