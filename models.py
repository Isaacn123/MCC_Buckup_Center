import sqlalchemy as _sql
import sqlalchemy.orm as _orm
import passlib.hash as _hash
import database as _database
from datetime import datetime as _dt
import json as _json



def _norm_folder_prefix(p: str):
    p = (p or "").strip().replace("\\", "/")
    if not p:
        return None
    return p if p.endswith("/") else p + "/"



class User(_database.Base):
    __tablename__ = "users"

    id = _sql.Column(_sql.Integer,primary_key=True,index=True)
    email = _sql.Column(_sql.String,unique=True,index=True)
    name = _sql.Column(_sql.String)
    hashed_password = _sql.Column(_sql.String)
    role = _sql.Column(_sql.String, default="user")  # "admin" | "user"
    allowed_prefix = _sql.Column(_sql.String, nullable=True)  # legacy: first folder
    allowed_prefixes = _sql.Column(_sql.Text, nullable=True)  # JSON list of folder prefixes
    is_active = _sql.Column(_sql.Boolean, default=True)
    date_created = _sql.Column(_sql.DateTime,default=_dt.utcnow)
    uploads = _orm.relationship("Upload",back_populates="owner")

    def verify_password(self,password:str):
        return _hash.bcrypt.verify(password,self.hashed_password)
    
    def set_password(self,password:str):
        self.hashed_password = _hash.bcrypt.hash(password)
        print(f"PASS: {self.hashed_password}")

    def get_allowed_prefixes_list(self):
        out = []
        if self.allowed_prefixes:
            try:
                data = _json.loads(self.allowed_prefixes)
                if isinstance(data, list):
                    for x in data:
                        n = _norm_folder_prefix(str(x) if x is not None else "")
                        if n:
                            out.append(n)
            except Exception:
                pass
        if not out and self.allowed_prefix:
            n = _norm_folder_prefix(self.allowed_prefix)
            if n:
                out.append(n)
        seen, res = set(), []
        for p in out:
            if p not in seen:
                seen.add(p)
                res.append(p)
        return res

    def set_allowed_prefixes_list(self, prefixes):
        norm = []
        seen = set()
        for x in prefixes or []:
            n = _norm_folder_prefix(str(x) if x is not None else "")
            if n and n not in seen:
                seen.add(n)
                norm.append(n)
        self.allowed_prefixes = _json.dumps(norm) if norm else None
        self.allowed_prefix = norm[0] if norm else None
    
    def to_dict_user(self):
        prefs = self.get_allowed_prefixes_list()
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email,
            "hashed_password":self.hashed_password,
            "role": self.role,
            "allowed_prefix": self.allowed_prefix,
            "allowed_prefixes": prefs,
            "is_active": self.is_active,
            "date_created":self.date_created.isoformat() if self.date_created else None,
        }
    
class Upload(_database.Base):
    __tablename__ = "uploads"
    id =  _sql.Column(_sql.Integer,primary_key=True,index=True)
    upload_file_name = _sql.Column(_sql.String)
    owner_id = _sql.Column(_sql.Integer,_sql.ForeignKey("users.id"))
    date_created = _sql.Column(_sql.DateTime,default=_dt.utcnow)

    owner = _orm.relationship("User",back_populates='uploads')