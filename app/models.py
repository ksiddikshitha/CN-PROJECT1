from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db

def now(): return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True); name=db.Column(db.String(100), nullable=False)
    email=db.Column(db.String(254), unique=True, index=True, nullable=False)
    password_hash=db.Column(db.String(256), nullable=False); created_at=db.Column(db.DateTime(timezone=True), default=now)
    def set_password(self,p): self.password_hash=generate_password_hash(p)
    def check_password(self,p): return check_password_hash(self.password_hash,p)

class Folder(db.Model):
    id=db.Column(db.Integer,primary_key=True); owner_id=db.Column(db.Integer,db.ForeignKey('user.id'),index=True,nullable=False)
    name=db.Column(db.String(120),nullable=False); parent_id=db.Column(db.Integer,db.ForeignKey('folder.id'),index=True)
    deleted_at=db.Column(db.DateTime(timezone=True))
    created_at=db.Column(db.DateTime(timezone=True),default=now)

class File(db.Model):
    id=db.Column(db.Integer,primary_key=True); owner_id=db.Column(db.Integer,db.ForeignKey('user.id'),index=True,nullable=False)
    folder_id=db.Column(db.Integer,db.ForeignKey('folder.id'),index=True); name=db.Column(db.String(255),nullable=False)
    storage_key=db.Column(db.String(80),unique=True,nullable=False); size=db.Column(db.BigInteger,nullable=False)
    mime_type=db.Column(db.String(120),nullable=False); sha256=db.Column(db.String(64),nullable=False,index=True)
    created_at=db.Column(db.DateTime(timezone=True),default=now); updated_at=db.Column(db.DateTime(timezone=True),default=now,onupdate=now)
    deleted_at=db.Column(db.DateTime(timezone=True)); is_favorite=db.Column(db.Boolean,default=False)
    owner=db.relationship('User',foreign_keys=[owner_id])

class ShareLink(db.Model):
    id=db.Column(db.Integer,primary_key=True); file_id=db.Column(db.Integer,db.ForeignKey('file.id'),index=True,nullable=False)
    owner_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False); recipient_id=db.Column(db.Integer,db.ForeignKey('user.id'),index=True)
    token_hash=db.Column(db.String(64),unique=True,index=True,nullable=False)
    password_hash=db.Column(db.String(256)); allow_download=db.Column(db.Boolean,default=True); expires_at=db.Column(db.DateTime(timezone=True))
    download_limit=db.Column(db.Integer); download_count=db.Column(db.Integer,default=0); revoked=db.Column(db.Boolean,default=False)
    created_at=db.Column(db.DateTime(timezone=True),default=now)
    file=db.relationship('File')
    recipient=db.relationship('User',foreign_keys=[recipient_id])
    owner=db.relationship('User',foreign_keys=[owner_id])

class PasswordResetToken(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),index=True,nullable=False)
    token_hash=db.Column(db.String(64),unique=True,index=True,nullable=False)
    expires_at=db.Column(db.DateTime(timezone=True),nullable=False); used_at=db.Column(db.DateTime(timezone=True))
    created_at=db.Column(db.DateTime(timezone=True),default=now)

class ActivityLog(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),index=True)
    action=db.Column(db.String(40),nullable=False); detail=db.Column(db.String(255),default=''); method=db.Column(db.String(10),default=''); endpoint=db.Column(db.String(120),default='')
    status=db.Column(db.Integer,default=200); transfer_size=db.Column(db.BigInteger,default=0); created_at=db.Column(db.DateTime(timezone=True),default=now,index=True)

class Favourite(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    file_id=db.Column(db.Integer,db.ForeignKey('file.id'),nullable=False); __table_args__=(db.UniqueConstraint('user_id','file_id'),)

class Notification(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False,index=True)
    message=db.Column(db.String(255),nullable=False); read=db.Column(db.Boolean,default=False); created_at=db.Column(db.DateTime(timezone=True),default=now)
