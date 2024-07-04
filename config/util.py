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

    # Flask-Mail configuration
    MAIL_SERVER = 'pro.turbo-smtp.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD') 
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')

