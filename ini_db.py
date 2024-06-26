import services as _serv
import secrets

if __name__ == "__main__" :
    _serv._create_database()
    secrets_key = secrets.token_hex(16)
    print(f"Key sec: {secrets_key}")
    print("Data Created Here...")
