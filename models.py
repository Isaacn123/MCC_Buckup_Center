import sqlalchemy as _sql
import sqlalchemy.orm as _orm
import passlib.hash as _hash
import database as _database
from datetime import datetime as _dt



class User(_database.Base):
    __tablename__ = "users"

    id = _sql.Column(_sql.Integer,primary_key=True,index=True)
    email = _sql.Column(_sql.String,unique=True,index=True)
    name = _sql.Column(_sql.String)
    hashed_password = _sql.Column(_sql.String)
    date_created = _sql.Column(_sql.DateTime,default=_dt.utcnow)
    uploads = _orm.relationship("Upload",back_populates="owner")

    def verify_password(self,password:str):
        return _hash.bcrypt.verify(password,self.hashed_password)
    
    def set_password(self,password:str):
        self.hashed_password = _hash.bcrypt.hash(password)
        print(f"PASS: {self.hashed_password}")
    
    def to_dict_user(self):
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email,
            "hashed_password":self.hashed_password,
            "date_created":self.date_created.isoformat() if self.date_created else None,
        }
    
class Upload(_database.Base):
    __tablename__ = "uploads"
    id =  _sql.Column(_sql.Integer,primary_key=True,index=True)
    upload_file_name = _sql.Column(_sql.String)
    owner_id = _sql.Column(_sql.Integer,_sql.ForeignKey("users.id"))
    date_created = _sql.Column(_sql.DateTime,default=_dt.utcnow)

    owner = _orm.relationship("User",back_populates='uploads')