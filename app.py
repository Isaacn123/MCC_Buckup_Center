from flask import  Flask, jsonify, request, send_file, Response,render_template
from a2wsgi import ASGIMiddleware
from b2sdk.v2 import InMemoryAccountInfo, B2Api
from flask_cors import CORS
import os
import io

app = Flask(__name__,static_folder='public')

CORS(app, origins=[
    "http://127.0.0.1.tiangolo.com",
    "https://127.0.0.1.tiangolo.com",
    "http://127.0.0.1",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5500",
])

info = InMemoryAccountInfo()
b2_api = B2Api(info)
app_key = "K005RVRokrCOJcQ9tSDLq8aDHajziKM"
app_key_ID = "005daaffbb3b1180000000002"
bucket_name = "mc-upload-bk"
b2_api.authorize_account('production', application_key=app_key, application_key_id=app_key_ID)

@app.route('/get_upload_url/', methods=['GET'])
def get_upload_url():
    file_name = request.args.get('file_name')
    bucket = b2_api.get_bucket_by_name(bucket_name=bucket_name)
    upload_response_url = bucket.upload_local_file(
        file_name=file_name,
    )
    return jsonify({
        "uploadUrl": upload_response_url["url"],
        "authorizationToken": upload_response_url["authorizationToken"]
    })
    
@app.route("/upload", methods=['POST'])
def upload():
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


@app.route('/')
def read_root():
    # return {"message": "It works! Am testing now again"}
    return render_template("index.html")

# application = ASGIMiddleware(app)
if __name__ == "__main__":
    app.run(debug=True)

