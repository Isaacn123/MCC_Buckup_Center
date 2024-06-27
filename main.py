from flask import Flask,request,jsonify,abort, render_template,redirect,session
from flask_restx import Api, Resource,fields

import services as _service
import  schemas as  _sechma
import os
import secrets
from b2sdk.v2 import InMemoryAccountInfo,B2Api
from config.util import *
# from flask_cors import CORS

app = Flask(__name__)
app.config['SWAGGER_UI_DOC_EXPANSION'] = 'list' #'full'
info = InMemoryAccountInfo()
b2_api = B2Api(info)
b2_api.authorize_account('production', application_key=app_key, application_key_id=app_key_ID)
# Generate or load secret key
def generate_secret_key():
    return secrets.token_hex(16)

app.secret_key = os.getenv('SECRET_KEY') or generate_secret_key()
api = Api(app=app)



user_model = api.model('User',{
"email": fields.String(required=True, description="Username can not be blank"),
"password": fields.String(required=True, description="Password can not be blank")
})

@app.route('/login')
def read_root():
    # return {"message": "It works! Am testing now again"}
    return render_template("signin.html")
        # if request.headers.get("Accept") == "application/json":
        #     return jsonify(message='This endpoint return Html, Json')
        # return render_template("signin.html")

@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session and session['logged_in']:
         # Access the token from the session
        token = session.get('token_ms', None)
        print(token)
        return render_template("dashboad.html",token=token)
    else:
        return redirect('/login')
    
class CreateUser(Resource):
    @api.doc(description='Create current user information')
    @api.expect(user_model)  #inputs data matching the user model
    
    def post(self):
        print("am testing")
        user_data = request.get_json()
        user = _sechma.UserCreate(**user_data)
        print("logged")
        with _service.get_db() as db:
            print("logged")
            user_db = _service.get_user_by_email(user.email,db)
            
            if user_db:
                abort(400,description="Email already exists")
            
            user_obj = _service.createUser(user,db)
            # token = _service.create_token(user_obj)

            # return jsonify(token=token),201
            return _service.create_token(user_obj)
        
class GenerateToken(Resource):
    def post(self):
        print("Received form data:")
        return _service.generate_token()

class GetUser(Resource):
    @api.doc(description='Get current user information')
    def get(self):
        user = _service.get_current_user()
        return jsonify(user)

# @app.route("/upload", methods=['POST'])
class UploadFiles(Resource):
    def post(self):
        try:
            file = request.files['file']
            file_Content = file.read()
            file_stream = io.BytesIO(file_Content)
            print(f"File to be : {file.filename}")

            bucket = b2_api.get_bucket_by_name(bucket_name)
            bucket.upload_bytes(
                data_bytes=file_stream.getvalue(),
                file_name=file.filename
            )

            return jsonify({"message": f"File {file.filename} uploaded successfully"})

        except Exception as e:
            return jsonify({"message": f"Failed to upload file: {str(e)} "}), 500
    

api.add_resource(CreateUser, '/api/signup')
api.add_resource(GenerateToken, '/api/token')
api.add_resource(GetUser, '/api/user/me')
api.add_resource(UploadFiles,'/upload')
# api.add_resource(MainPage,'/login')


# @app.route("/signin", method=["POST"])
# def CreateUser():
#     user_data = request.get_json()
#     user = _schema.UserCreate(**user_data)

#     with _service.get_db() as db:
#         user_db = _service.get_user_by_email(user.email,db)
        
#         if user_db:
#             abort(400,description="Email already exists")
        
#         user_obj = _service.createUser(user,db)
#         token = _service.create_token(user_obj)

#         return jsonify(token=token),201

# @app.route("/api/token",method=["POST"])
# def generate_token():
#     print("Received form data:")
#     return _service.generate_token()


# @app.route("/api/user/me", method=["GET"])
# def get_user():
#     user = _service.get_currect_user()
#     return jsonify(user)


if __name__ == '__main__':
    app.run(debug=True)

