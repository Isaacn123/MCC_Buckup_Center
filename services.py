from contextlib import contextmanager
import sqlalchemy as _sql
import sqlalchemy.orm as _orm
import passlib.hash as _hash
import jwt as _jwt
import email_validator as _email_valid
import database as _database
import  models as _models
import schemas as _schema
from flask import abort,request,jsonify,session
from b2sdk.v1 import B2Api


JWT_SECRET = ""
SessionLocal = _database.SessionLocal

def _create_database():
    return _database.Base.metadata.create_all(bind=_database.engine)

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db

    finally:

        db.close()

def createUser(user:_schema.UserCreate, db: _orm.Session):
    try:
        valid = _email_valid.validate_email(user.email)
        email = valid.email
    except _email_valid.EmailNotValidError:
        abort(400,description="Please enter a valid email")
    
    user_obj = _models.User(email=email,name=user.name,hashed_password=_hash.bcrypt.hash(user.password))
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    return user_obj
    
def get_user_by_email(email:str, db:_orm.Session):

    return  db.query(_models.User).filter(_models.User.email == email).first()

def create_token(user:_models.User):
    user_obj = user.to_dict_user()
    token = _jwt.encode(user_obj,JWT_SECRET, algorithm="HS256")

    # return {'access_token':token, 'token_type':'bearer'}
    return dict(access_token=token,token_type="bearer")

def get_current_user():
    token = None

    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split()[1]
    
    if not token:
        abort(401,description="Token is missing")
    
    try:
        payload  =_jwt.decode(token,JWT_SECRET,algorithms=["HS256"])
        user_id = payload.get("id")
        if user_id is None:
            abort(401,description="Invalid token") 
        
        with get_db() as db:
            user = db.query(_models.User).filter(_models.User.id == user_id).first()
            if user is None:
                abort(401,description="User not found") 


    except _jwt.ExpiredSignatureError:
         abort(401, description="Token has expired")
    except _jwt.InvalidTokenError:
        abort(401, description="Invalid token")
    except Exception:
        abort(401, description="Invalid email or password")
    
    user_schema = _schema.User.from_orm(user)
    return user_schema.dict()


def authenticate_user(email:str,password:str,db:_orm.Session):
    user = get_user_by_email(email=email,db=db)
    if user:
        print(f"User found: {user.email}")
        hashed_password2 = _hash.bcrypt.hash(password)
        # print(f"Stored hashed password: {user.hashed_password}")
        if user.verify_password(password=password):
            print("Password verification successful")
            return user
        else:
            print("Password verification failed")
            return None
    else:
        print("User not Found")
        return None


def generate_token():
    data = request.json
    email = data.get('username')
    password =  data.get('password')

    if not email or not password:
        abort(400, description="Missing username or password")
    
    with get_db() as db:
        user = authenticate_user(email=email,password=password,db=db)

        if not user:
            abort(400, description="Invalid Credentials")

        token = create_token(user=user)
        if token:
            session['logged_in'] = True
            session['token_ms'] = token['access_token']
        # return jsonify(token)
        return token
    

