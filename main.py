from flask import Flask,request,jsonify,abort, render_template,redirect,session
from flask_restx import Api, Resource,fields

import services as _service
import  schemas as  _sechma
import os
import secrets
from b2sdk.v2 import InMemoryAccountInfo,B2Api
from config.util import *
import io
import logging

# from flask_cors import CORS

app = Flask(__name__)
app.config['SWAGGER_UI_DOC_EXPANSION'] = 'list' #'full'
info = InMemoryAccountInfo()
b2_api = B2Api(info)
b2_api.authorize_account('production', application_key=app_key, application_key_id=app_key_ID)
bucket = b2_api.get_bucket_by_name(bucket_name=bucket_name)

logger = logging.getLogger(__name__)

# Generate or load secret key
def generate_secret_key():
    return secrets.token_hex(16)

app.secret_key = os.getenv('SECRET_KEY') or generate_secret_key()
api = Api(app=app, doc='/api/v2')



user_model = api.model('User',{
"email": fields.String(required=True, description="Username can not be blank"),
"name": fields.String(required=True,description="User name can not be blank"),
"password": fields.String(required=True, description="Password can not be blank")
})

folder_name = api.model('Folder',{
    'folder_name': fields.String(required=True,description="Name of the folder to create")
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


@app.route('/uploadfiles')
def uploadfiles():
    if 'logged_in' in session and session['logged_in']:
         # Access the token from the session
        token = session.get('token_ms', None)
        return render_template("index.html",token=token)
    else:
        return redirect('/login')

@app.route("/download/<file_name>")
def download(file_name):
    file_info = bucket.get_file_info_by_name(file_name=file_name)
    print(f"FILE INFO: {file_info}")
    return jsonify(file_info)
    
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
            # print(f"File to be : {request.folder_name}")
            file = request.files['file']
            file_Content = file.read()
            file_stream = io.BytesIO(file_Content)
           

            folder_name = request.form.get('folder_name', '').strip()

            # print(f"fold: {request.files['folder_name']}")
            print(f"Folder: {folder_name}")
            
            if folder_name:
                 file_name = f"{folder_name}{file.filename}"
                # file_name = folder_name + file.filename
            # folder_name = request.form.get('folder_name','')
            # if folder_name:
            #     folder_name = folder_name.rstrip('/') + '/'
            
            # file_path = folder_name + file.filename
            print(f"PATH: {file_name}")

            bucket.upload_bytes(
                data_bytes=file_stream.getvalue(),
                # file_name=file.filename
                file_name=file_name
            )

            # return jsonify({"message": f"File {file.filename} uploaded successfully"})
            # logger.info(f"Uploading file {file_name} to bucket {bucket_name}")
            success_message = f"File '{file.filename}' uploaded successfully to '{file_name}'"
            return jsonify({"message": success_message})

        except Exception as e:
            return jsonify({"message": f"Failed to upload file: {str(e)}"})

class CreateB2BucketFolder(Resource):
    @api.doc(description='Create A Folder in the Bucket')
    @api.expect(folder_name)
    def post(self):
            data = request.get_json()
            folder_name = data.get('folder_name')

            if not folder_name:
                return {"message": "folder_name is required"}
            
            if not folder_name.endswith('/'):
                folder_name +='/'

            # Add a placeholder file name within the "folder" 
            placeholder_file = folder_name + 'folder.txt'

            bucket.upload_bytes(b'',placeholder_file)

            return {"message": f"Folder '{folder_name}' created successfully in bucket '{bucket_name}'"}

class GETALLBUCKET2FOLDERS(Resource):
    def get(self):
        try:
            file_versions = bucket.ls(latest_only=True)
            
            # folders = []
        # for file_version, _ in file_version:
        #     file_name = file_version.file_name
        #     print(f"Checking file: {file_name}")
        #     if file_name.endswith('/'):
        #         folders.append(file_name)

            # folders = [file_version.file_name for file_version, _ in file_versions]
            folders = []
            for file_version,folder_name in file_versions:
               
                if folder_name is not None and folder_name.endswith('/'):
                    folders.append(folder_name)
                    print(f"folders: {folders}")
                else:
                    print("no match FOund.")


            return jsonify(folders)

            # print("List of Files")
            # for file_name in folders:
            #     print(file_name)
            
            # return jsonify({"folders": folders})
        
        except Exception as e:

            return jsonify({"error:": str(e)})

class GETALLFILES(Resource):
    @api.expect(folder_name)
    def post(self):
        
        try:
            data = request.json
            print(data)
            folder_name = data.get('folder_name','').strip()
            # print(f"FOLDER: {folder_name}")
            if not folder_name:
                return jsonify({"error": "Folder name is required"})
            file_versions = bucket.ls(folder_to_list=folder_name,latest_only=True)
            files = [file_version.file_name for file_version, _ in file_versions if not file_version.file_name.endswith('/')]

            return jsonify({"files":files})

        except Exception as e:
            return jsonify({"error": str(e)})

        # print("Folders in the bucket:")
        # if folders:
        #     print("Folders in the BUCKT")
        #     for folder in folders:
        #         print(f"Folders : {folder}")
        # else :
        #     print("No FOLDERS")
            
        # return folders

# @app.route('/')
# def main():
    # return {"message": "It works! Am testing now again"}
    # return render_template("dashboard.html")


    
api.add_resource(CreateB2BucketFolder, '/create_b2_folder')
api.add_resource(GETALLBUCKET2FOLDERS,'/get_all_buckets')
api.add_resource(GETALLFILES,'/list_all_files')
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

