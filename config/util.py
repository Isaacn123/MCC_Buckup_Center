from dotenv import load_dotenv
import os
# load .env file
load_dotenv()

app_key = os.getenv('APP_KEY') 
app_key_ID =  os.getenv('APP_KEY_ID') 
bucket_name = os.getenv('BUCKET_NAME') 

# config.py
class Config:
    JWT_SECRET = os.getenv('JWT_SECRET')
    RESET_TOKEN_EXPIRATION = 1  # Token expiration time in hours

    # Upload sizing (Flask will reject bigger requests with 413)
    # Set env `MAX_UPLOAD_MB` (e.g. 2048 for 2GB).
    MAX_UPLOAD_MB = int(os.getenv('MAX_UPLOAD_MB') or "2048")
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024

    # Flask-Mail configuration
    MAIL_SERVER = 'pro.turbo-smtp.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD') 
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')

