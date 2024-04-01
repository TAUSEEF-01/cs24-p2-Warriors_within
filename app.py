from flask import Flask, jsonify, request,render_template, redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from psutil import users

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    
    # write code ------->
    phoneNumber = db.Column(db.String(20), nullable=False, unique = True)
    role = db.Column(db.String(20), nullable=True, default='Unassigned')


    def __init__(self,email,password,name,phoneNumber,role):
    # def __init__(self,email,password,name,phoneNumber):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.phoneNumber = phoneNumber
        self.role = role
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))
    
    # def set_password(self,password):
    #     self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

with app.app_context():
    db.create_all()
    
    
@app.route('/')
def root():
    return render_template('root.html')


@app.route('/auth')
def index():
    return render_template('index.html')






@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phoneNumber = request.form['phoneNumber']
        role = request.form['role']

        # Check if any field is empty
        if not name or not email or not password or not phoneNumber or not role:
            return render_template('register.html', error='Please fill in all the fields.')

        new_user = User(name=name, email=email, password=password, phoneNumber=phoneNumber, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/auth/login')

    return render_template('register.html')




@app.route('/auth/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/auth/dashboard')
        else:
            return render_template('login.html',error='Invalid user')

    return render_template('login.html')




@app.route('/auth/dashboard')
def dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html',user=user)
    
    return redirect('/auth/login')




@app.route('/auth/logout')
def logout():
    session.pop('email',None)
    return redirect('/auth/login')





@app.route('/auth/reset-password/initiate', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        old_password = request.form['prev_password']
        new_password = request.form['new_password']

        # Find the user by email
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Check if the old password matches the stored password
            if user.check_password(old_password):
                # Update the user's password with the new password
                
                user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                db.session.commit()  # Commit the changes to the database
                return redirect('/auth')  # Redirect to login page after resetting password
            else:
                return render_template('reset-password.html', error='Old password does not match')
        else:
            return render_template('reset-password.html', error='Invalid email')
    
    return render_template('reset-password.html')



# def is_system_admin():
#     # Assuming you have the user's email stored in the session after login
#     if 'email' in session:
#         user = User.query.filter_by(email=session['email']).first()
#         # Assuming you have a 'role' attribute in your User model
#         if user and user.role == 'admin':
#             return True
#     return False




@app.route('/users', methods=['GET'])
def list_users():
    # if is_system_admin():  # Assuming you have a function to check if the user is a system admin
    if request.method == 'GET':
        users = User.query.all()
        user_list = [{'id': user.id, 'name': user.name, 'email': user.email, 'phoneNumber': user.phoneNumber, 'role': user.role} for user in users]
        return jsonify({'users': user_list}), 200
    else:
        return jsonify({'error': 'Unauthorized'}), 401



@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # if is_system_admin():  # Assuming you have a function to check if the user is a system admin
    if request.method == 'GET':
        user = User.query.get(user_id)
        if user:
            user_details = {'id': user.id, 'name': user.name, 'email': user.email, 'phoneNumber': user.phoneNumber, 'role': user.role}
            return jsonify(user_details), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    else:
        return jsonify({'error': 'Unauthorized'}), 401




# @app.route('/users', methods=['POST'])
# def create_user():
#     # Check if the request method is POST
#     if request.method == 'POST':
#         # Check if the user is a system admin (you can replace this condition with your own logic)
#         # if is_system_admin():
#         # Assuming the request contains JSON data with user details
#         user_data = request.json

#         # Extract user details from JSON data
#         name = user_data.get('name')
#         email = user_data.get('email')
#         phoneNumber = user_data.get('phoneNumber')
#         role = user_data.get('role')
#         password = user_data.get('password')  # Assuming password is included in the request

#         # Validate if all required fields are present
#         if not name or not email or not phoneNumber or not role or not password:
#             return jsonify({'error': 'Missing required fields'}), 400

#         # Check if the email is already in use
#         if User.query.filter_by(email=email).first():
#             return jsonify({'error': 'Email already exists'}), 409

#         # Create a new user instance
#         new_user = User(name=name, email=email, phoneNumber=phoneNumber, role=role)

#         # Hash the password before storing it
#         # new_user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

#         # Add the new user to the database
#         db.session.add(new_user)
#         db.session.commit()

#         # Return success response
#         return jsonify({'message': 'User created successfully'}), 201

#     # Return unauthorized error if request method is not POST
#     return jsonify({'error': 'Unauthorized'}), 401




@app.route('/users', methods=['POST'])
def create_user():
    # Check if the request method is POST
    if request.method == 'POST':
        # Assuming the request contains JSON data with user details
        user_data = request.json

        # Extract user details from JSON data
        name = user_data.get('name')
        email = user_data.get('email')
        phoneNumber = user_data.get('phoneNumber')
        role = user_data.get('role')
        password = user_data.get('password')  # Assuming password is included in the request

        # Validate if all required fields are present
        if not name or not email or not phoneNumber or not role or not password:
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if the email is already in use
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409

        # Create a new user instance
        new_user = User(name=name, email=email, phoneNumber=phoneNumber, role=role, password=password)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Return success response
        return jsonify({'message': 'User created successfully'}), 201

    # Return unauthorized error if request method is not POST
    return jsonify({'error': 'Unauthorized'}), 401




@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    # Check if the request method is PUT
    if request.method == 'PUT':
        # Assuming the request contains JSON data with updated user details
        updated_data = request.json

        # Retrieve the user from the database by user_id
        user = User.query.get(user_id)

        # Check if the user exists
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user:
            # Update the user's details
            if 'name' in updated_data:
                user.name = updated_data['name']
            if 'email' in updated_data:
                user.email = updated_data['email']
            if 'phoneNumber' in updated_data:
                user.phoneNumber = updated_data['phoneNumber']
            if 'role' in updated_data:
                user.role = updated_data['role']
            
            # Commit the changes to the database
            db.session.commit()

            # Return success response
            return jsonify({'message': 'User details updated successfully'}), 200
        else:
            return jsonify({'error': 'Unauthorized'}), 401

    # Return unauthorized error if request method is not PUT
    return jsonify({'error': 'Method Not Allowed'}), 405





@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # Check if the request method is DELETE
    if request.method == 'DELETE':
        # Check if the user is a system admin (you can replace this condition with your own logic)
        # if is_system_admin():
            # Find the user by user ID
            user = User.query.get(user_id)

            # Check if the user exists
            if user:
                # Delete the user from the database
                db.session.delete(user)
                db.session.commit()
                return jsonify({'message': 'User deleted successfully'}), 200
            else:
                return jsonify({'error': 'User not found'}), 404
        # else:
        #     return jsonify({'error': 'Unauthorized'}), 401

    # Return unauthorized error if request method is not DELETE
    return jsonify({'error': 'Method Not Allowed'}), 405




@app.route('/users/roles', methods=['GET'])
def list_roles():
    # Retrieve all distinct roles from the database
    roles = User.query.with_entities(User.role).distinct().all()
    
    # Extract role names from the result
    role_names = [role[0] for role in roles]
    
    # Return the list of roles as JSON response
    return jsonify({'roles': role_names}), 200





@app.route('/users/<int:user_id>/roles', methods=['PUT'])
def update_user_roles(user_id):
    # Check if the request method is PUT
    if request.method == 'PUT':
        # Check if the user is a system admin (you can replace this condition with your own logic)
        # if is_system_admin():
            # Retrieve the user from the database based on user ID
            
            updated_data = request.json
            
            user = User.query.get(user_id)

            # Check if the user exists
            if user:
                # Get the roles data from the request
                roles_data = request.json.get('roles')

                # Update user's roles
                # user.roles = roles_data
                user.role = updated_data['role']

                # Commit changes to the database
                db.session.commit()

                return jsonify({'message': 'User roles updated successfully'}), 200
            else:
                return jsonify({'error': 'User not found'}), 404
        # else:
        #     return jsonify({'error': 'Unauthorized'}), 401

    # Return unauthorized error if request method is not PUT
    return jsonify({'error': 'Method Not Allowed'}), 405



if __name__ == '__main__':
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