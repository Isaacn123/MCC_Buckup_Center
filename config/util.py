
app_key = "K005RVRokrCOJcQ9tSDLq8aDHajziKM"
app_key_ID = "005daaffbb3b1180000000002"
bucket_name = "mc-upload-bk"

# config.py
class Config:
    JWT_SECRET = '90cf9174c60f0c77dd6706df7176a155'
    RESET_TOKEN_EXPIRATION = 1  # Token expiration time in hours

    # Flask-Mail configuration
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your_email@example.com'
    MAIL_PASSWORD = 'your_email_password'
    MAIL_DEFAULT_SENDER = 'your_email@example.com'

