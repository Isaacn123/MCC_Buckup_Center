from pydantic import BaseModel
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

    class Config:
        from_attributes=True

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