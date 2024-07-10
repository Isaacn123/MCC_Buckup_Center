from flask import Flask,request,jsonify,abort, render_template,redirect,session
from flask_restx import Api, Resource,fields

import services as _service
import models as _model
import  schemas as  _sechma
import os
import secrets
from b2sdk.v2 import InMemoryAccountInfo,B2Api
from config.util import *
import io
import logging
from datetime import datetime, timedelta
import jwt as _jwt
from flask_mail import Message, Mail
from config.util import Config
from itsdangerous import TimedSerializer, SignatureExpired, BadSignature

# from flask_cors import CORS

app = Flask(__name__)
app.config['SWAGGER_UI_DOC_EXPANSION'] = 'list' #'full'
info = InMemoryAccountInfo()
b2_api = B2Api(info)
b2_api.authorize_account('production', application_key=app_key, application_key_id=app_key_ID)
bucket = b2_api.get_bucket_by_name(bucket_name=bucket_name)

# Initializing my config settings
app.config.from_object(Config)
mail = Mail(app)


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
email_address = api.model('Password', {
    "email":fields.String(required=True,description="Email can't be blank")
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

@app.route('/passwordreset')
def resetPassword():

    return render_template('reset_password.html')

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

@app.route("/api/logout")
def logout_user():
    session.clear()
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
        
class GETALLFOLDERSANDFILES(Resource):
    def get(self):
        try:
          response  = bucket.ls(latest_only=True)
          all_files = []
          for file_version,folder_name in response:
              path_url_name = get_presigned_url(bucket_name,file_version.file_name)
              
              if folder_name is not None:
                  
                  all_files.append({
                       "type":"folder",
                       "folder_name":folder_name,
                       "date": file_version.upload_timestamp
                  })
              else :
                   all_files.append({
                       "name":file_version.file_name,
                       "info":file_version.file_info,
                       "type":"file",
                       "url":path_url_name,
                       "content_type":file_version.content_type,
                       "date": file_version.upload_timestamp,
                       "folder_name":folder_name
                  })
              
            #   if 'is_folder' in file_version and file_version['is_folder']:
            #       all_files.append({
            #           "name":file_version['name'],
            #           "path":file_version['path'],
            #           "type":"folder",
            #           "folder_name":file_version['name']
            #                         })
            #   else:
            #       file_name = file_version['name']
            #       folder = file_version.get('folder_name',"")

            #       all_files.append({
            #           "name": file_name,
            #           "path":file_version["path"],
            #           "type": "file",
            #           "folder_name": folder
            #       })
                  
              
            #   if folder_name is not None:
            #       all_files.append({"file_version": file_version.file_name, "folder_name": folder_name})
            #   else:
            # all_files.append({"file_version":file_version})
                #   return jsonify({"message":"No Folder name found"})         
          
          return jsonify(all_files)
          
        except Exception as e:

            return jsonify({"message": f"Failed to return all the files {str(e)}"})
        



class CreateB2BucketFolder(Resource):
    @api.doc(description='Create A Folder in the Bucket')
    @api.expect(folder_name)
    def post(self):
            data = request.get_json()
            folder_name = data.get('folder_name')
            create_folder =  data.get('parent_folder')

            if not folder_name:
                return {"message": "folder_name is required"}
            

            
            if not folder_name.endswith('/'):
                folder_name +='/'

            # Add a placeholder file name within the "folder" 
            placeholder_file = create_folder + folder_name  + 'folder.txt'

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

def get_presigned_url(bucket_name,file_name):

    # download_url = b2_api.get_download_url_for_file_name(file_name=file_name,bucket_name=bucket_name)
    download_url = b2_api.get_download_url_for_file_name(bucket_name=bucket_name,file_name=file_name)

    base_url = 'https://f000.backblazeb2.com/file'
    presigned_url = f"{base_url}/{bucket_name}/{file_name}?Authorization={download_url}"  
    
    return download_url

def generate_auth_token(file_name, expiration=3600):
    serializer = TimedSerializer(os.getenv('SECRET_KEY'), expires_in=expiration)
    return serializer.dumps(file_name)

def verify_auth_token(token):
    serializer = TimedSerializer(os.getenv('SECRET_KEY'))
    try:
        return serializer.loads(token)
    except SignatureExpired:
        # Token expired
        return None
    except BadSignature:
        # Invalid token
        return None

def generate_secure_url(base_url, token):
    return f"{base_url}?Authorization={token}"

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

            # files = [file_version.file_name for file_version, _ in file_versions if not file_version.file_name.endswith('/')]
            file_results = []
            common_prefix = get_common_prefix(folder_name)
            for file_version,folder_name in file_versions:

                if folder_name is not None and folder_name.endswith('/'):
                    path_url_name = get_presigned_url(bucket_name,file_version.file_name)
                    token= generate_auth_token(file_version.file_name,3600)
                    secure_url = generate_secure_url(path_url_name,token=token)
                    file_results.append({
                        "folder_name":strip_prefix(folder_name,common_prefix),
                        "path":file_version.file_name,
                        "type":"folder"

                    })
                else:
                    file_results.append({
                        "name":strip_prefix(file_version.file_name,common_prefix),
                        "type":"file",
                        "url":secure_url,
                        "date": file_version.upload_timestamp,
                        "content_type":file_version.content_type,
                        "folder_name":folder_name

                    })

            return jsonify({"files":file_results})

        except Exception as e:
            return jsonify({"error": str(e)})

# @app.route('/forgotpassword', method=["POST"])
# def forgotpassword():
class FORGOTPASSWORD(Resource):
    @api.expect(email_address)
    def post(self):
        data = request.json
        email = data.get('email')

        if not email:
            raise jsonify({"error":"Email is required!"})
        
        user = _service.get_user(email=email)

        
        if not user:
            raise jsonify({"error": "User with this email does not exist"})
        
        expiration = datetime.utcnow() + timedelta(hours=Config.RESET_TOKEN_EXPIRATION)
        reset_token = _jwt.encode({"id":user.id, "exp": expiration}, Config.JWT_SECRET, algorithm="HS256")

        send_reset_email(user.email,reset_token)

        return jsonify({"message": "Password reset email sent"})
    
    

def send_reset_email(email,token):
    reset_url = f"{request.host_url}passwordreset?token={token}"
    msg = Message(
        subject="Password Reset Request",
        sender= Config.MAIL_DEFAULT_SENDER,
        recipients=[email],
        body=f"To reset your password, visit the following link:{reset_url}\n\n"
        f"If you did not make this request, please ignore this email."
    )

    mail.send(msg)


@app.route('/reset_password', methods=["POST"])
def reset_password():
        data = request.json
        token = data.get("token")
        new_password = data.get('new_password')

        if not token or not new_password:
            return jsonify({"error": "Token and new password are required"})
        
        try:
            payload = _jwt.decode(token,Config.JWT_SECRET, algorithms=["HS256"])
            user_id = payload.get("id")

            if user_id is None:
                return jsonify({"error":"Invalid token"})
            
            with _service.get_db() as db:
                user = db.query(_model.User).filter(_model.User.id == user_id).first()
            if not user:
                return jsonify({"error": "User not found"})
            
            # Update the user's password
            print(f"PAs_new: {new_password}")
            user.set_password(new_password)
            db.commit()
            
        except _jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"})
        except _jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"})

        return jsonify({"message": "Password has been reset"})

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
api.add_resource(FORGOTPASSWORD, '/forgot_password')

# Changing the Fetch method:
api.add_resource(GETALLFOLDERSANDFILES, '/list_folder_and_files')

# api.add_resource(MainPage,'/login')

def strip_prefix(text,prefix):
    if text and text.startswith(prefix):
        return text[len(prefix):]
    return text

def get_common_prefix(folder_name):
    if folder_name.endswith('/'):
        return folder_name
    return folder_name + '/'


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

