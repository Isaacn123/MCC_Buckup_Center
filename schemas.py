from pydantic import BaseModel
from typing import Optional, List
import datetime as _dt

class _BaseUser(BaseModel):
    email:str
    name:str

class UserCreate(_BaseUser):
    password:str

    class Config:
        from_attributes=True

class User(_BaseUser):
    id:int
    date_created:_dt.datetime
    role: Optional[str] = None
    allowed_prefix: Optional[str] = None
    allowed_prefixes: Optional[List[str]] = None
    is_active: Optional[bool] = None

    class Config:
        from_attributes=True


class AdminCreateUser(BaseModel):
    email: str
    name: str
    password: str
    role: str = "user"
    allowed_prefix: Optional[str] = None
    allowed_prefixes: Optional[List[str]] = None
    is_active: bool = True


class AdminUpdateUserAccess(BaseModel):
    user_id: int
    role: Optional[str] = None
    allowed_prefix: Optional[str] = None
    allowed_prefixes: Optional[List[str]] = None
    revoke_prefix: Optional[str] = None
    is_active: Optional[bool] = None

class _BaseUploads(BaseModel):
    name:str

class UploadCreate(_BaseUploads):
    pass

class Uploads(_BaseUploads):
    id:int
    owner_id:int
    date_created:_dt.datetime

    class Config:
        from_attributes=True