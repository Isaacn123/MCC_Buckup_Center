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


def ensure_db_schema():
    """
    Lightweight SQLite 'migration' to add new columns if missing.
    Safe to run on every startup.
    """
    engine = _database.engine
    with engine.connect() as conn:
        # Ensure tables exist first
        _database.Base.metadata.create_all(bind=engine)
        try:
            cols = conn.execute(_sql.text("PRAGMA table_info(users)")).fetchall()
            existing = {c[1] for c in cols}  # name is index 1
            alters = []
            if "role" not in existing:
                alters.append("ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'user'")
            if "allowed_prefix" not in existing:
                alters.append("ALTER TABLE users ADD COLUMN allowed_prefix VARCHAR")
            if "is_active" not in existing:
                alters.append("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
            for stmt in alters:
                conn.execute(_sql.text(stmt))
            if alters:
                conn.commit()
        except Exception:
            # If PRAGMA/ALTER fails (non-sqlite), skip quietly
            pass


def require_admin(user_dict: dict):
    if not user_dict:
        abort(401, description="Unauthorized")
    if not user_dict.get("is_active", True):
        abort(403, description="User is disabled")
    if user_dict.get("role") != "admin":
        abort(403, description="Admin required")


def enforce_prefix_access(user_dict: dict, target_prefix: str):
    """
    Enforce that non-admin users can only operate within allowed_prefix.
    If allowed_prefix is None/empty => deny by default (safer).
    """
    if not user_dict:
        abort(401, description="Unauthorized")
    if not user_dict.get("is_active", True):
        abort(403, description="User is disabled")
    if user_dict.get("role") == "admin":
        return
    allowed = (user_dict.get("allowed_prefix") or "").strip()
    if not allowed:
        abort(403, description="No folder access assigned")
    if not target_prefix.startswith(allowed):
        abort(403, description="Folder access denied")

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

def get_user(email:str):
    with get_db() as db:
            user = db.query(_models.User).filter(_models.User.email == email).first()
    
    return user


