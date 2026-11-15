import hashlib, secrets, mimetypes
from datetime import datetime, timedelta, timezone
from io import BytesIO
from flask import Blueprint, current_app, render_template, request, redirect, url_for, flash, abort, send_file, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from . import db, limiter
from .models import User, File, Folder, ShareLink, ActivityLog, Notification, PasswordResetToken, Favourite
from .storage import provider

bp=Blueprint('auth',__name__)
ALLOWED=set('pdf txt md csv png jpg jpeg gif webp mp4 mp3 wav zip doc docx xls xlsx ppt pptx'.split())
def log(action,detail='',size=0):
    db.session.add(ActivityLog(user_id=current_user.id if current_user.is_authenticated else None,action=action,detail=detail,method=request.method,endpoint=request.path,transfer_size=size)); db.session.commit()
def owned(i,deleted=False):
    f=File.query.filter_by(id=i,owner_id=current_user.id).first_or_404()
    if f.deleted_at and not deleted: abort(404)
    return f
def owned_folder(i,deleted=False):
    folder=Folder.query.filter_by(id=i,owner_id=current_user.id).first_or_404()
    if folder.deleted_at and not deleted: abort(404)
    return folder
def resolve_folder(raw):
    if raw in (None,''): return None
    if not raw.isdigit(): abort(400)
    return owned_folder(int(raw))
def folder_descends_from(folder_id,ancestor_id):
    node=db.session.get(Folder,folder_id)
    while node:
        if node.id==ancestor_id: return True
        node=db.session.get(Folder,node.parent_id) if node.parent_id else None
    return False
def category(name):
    e=name.rsplit('.',1)[-1].lower() if '.' in name else ''
    return next((k for k,v in {'Images':'jpg jpeg png gif webp','Documents':'pdf txt md csv doc docx xls xlsx ppt pptx','Videos':'mp4','Audio':'mp3 wav','Archives':'zip'}.items() if e in v.split()),'Other')
def content_matches_extension(name,data):
    ext=name.rsplit('.',1)[-1].lower()
    signatures={'pdf':data.startswith(b'%PDF-'),'png':data.startswith(b'\x89PNG\r\n\x1a\n'),
        'jpg':data.startswith(b'\xff\xd8\xff'),'jpeg':data.startswith(b'\xff\xd8\xff'),
        'gif':data.startswith((b'GIF87a',b'GIF89a')),'webp':len(data)>=12 and data[:4]==b'RIFF' and data[8:12]==b'WEBP',
        'zip':data.startswith(b'PK\x03\x04'),'docx':data.startswith(b'PK\x03\x04'),'xlsx':data.startswith(b'PK\x03\x04'),'pptx':data.startswith(b'PK\x03\x04'),
        'doc':data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),'xls':data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),'ppt':data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),
        'mp4':len(data)>=12 and data[4:8]==b'ftyp','mp3':data.startswith(b'ID3') or (len(data)>1 and data[0]==0xff and data[1]&0xe0==0xe0),
        'wav':data.startswith(b'RIFF') and data[8:12]==b'WAVE'}
    if ext in signatures: return signatures[ext]
    if ext in {'txt','md','csv'}: return b'\x00' not in data and (not data or _is_utf8(data))
    return False
def _is_utf8(data):
    try: data.decode('utf-8'); return True
    except UnicodeDecodeError: return False
def reserve_share_download(share):
    from sqlalchemy import update, or_
    result=db.session.execute(update(ShareLink).where(ShareLink.id==share.id,ShareLink.revoked.is_(False),or_(ShareLink.download_limit.is_(None),ShareLink.download_count<ShareLink.download_limit)).values(download_count=ShareLink.download_count+1))
    if result.rowcount!=1: db.session.rollback(); abort(404)
    db.session.commit()
@bp.route('/')
def home(): return render_template('landing.html')
@bp.route('/register',methods=['GET','POST'])
@limiter.limit('5 per minute')
def register():
    if request.method=='POST':
        name=request.form.get('name','').strip(); email=request.form.get('email','').strip(); password=request.form.get('password','')
        try: email=validate_email(email,check_deliverability=False).normalized.lower()
        except EmailNotValidError: email=''
        if not name or len(name)>100 or '@' not in email or len(password)<10 or password!=request.form.get('confirm'): flash('Check your details and use a matching password of 10+ characters.','error')
        elif User.query.filter_by(email=email).first(): flash('That email already has an account.','error')
        else:
            u=User(name=name,email=email); u.set_password(password); db.session.add(u); db.session.commit(); login_user(u); log('register','Account created'); return redirect(url_for('auth.dashboard'))
    return render_template('auth.html',mode='register')
@bp.route('/login',methods=['GET','POST'])
@limiter.limit('8 per minute')
def login():
    if request.method=='POST':
        u=User.query.filter_by(email=request.form.get('email','').strip().lower()).first()
        if u and u.check_password(request.form.get('password','')):
            login_user(u,remember=bool(request.form.get('remember'))); log('login','Successful sign in'); return redirect(url_for('auth.dashboard'))
        flash('Email or password is incorrect.','error')
    return render_template('auth.html',mode='login')
@bp.route('/forgot-password',methods=['GET','POST'])
@limiter.limit('3 per hour')
def forgot_password():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); user=User.query.filter_by(email=email).first()
        if user:
            raw=secrets.token_urlsafe(32); token=PasswordResetToken(user_id=user.id,token_hash=hashlib.sha256(raw.encode()).hexdigest(),expires_at=datetime.now(timezone.utc)+timedelta(minutes=30))
            db.session.add(token); db.session.commit()
            if current_app.config['PASSWORD_RESET_LOG_LINKS']:
                current_app.logger.info('Development password reset path for %s: %s',user.email,url_for('auth.reset_password',token=raw))
        flash('If that account exists, password reset instructions are available.','success')
    return render_template('forgot_password.html')
@bp.route('/reset/<token>',methods=['GET','POST'])
@limiter.limit('10 per hour')
def reset_password(token):
    token_hash=hashlib.sha256(token.encode()).hexdigest(); reset=PasswordResetToken.query.filter_by(token_hash=token_hash,used_at=None).first()
    now=datetime.now(timezone.utc)
    if not reset or reset.expires_at.replace(tzinfo=timezone.utc)<=now: abort(404)
    if request.method=='POST':
        password=request.form.get('password','')
        if len(password)<10 or password!=request.form.get('confirm'): flash('Use matching passwords with at least 10 characters.','error')
        else:
            user=db.session.get(User,reset.user_id); user.set_password(password); reset.used_at=now
            for previous in PasswordResetToken.query.filter_by(user_id=user.id,used_at=None).all(): previous.used_at=now
            db.session.commit(); flash('Password changed. Sign in with your new password.','success'); return redirect(url_for('auth.login'))
    return render_template('reset_password.html')
@bp.route('/logout',methods=['POST'])
@login_required
def logout():
    logout_user(); flash('You are signed out.','success'); return redirect(url_for('auth.home'))
@bp.route('/dashboard')
@login_required
def dashboard():
    fs=File.query.filter_by(owner_id=current_user.id,deleted_at=None).all(); used=sum(f.size for f in fs)
    distribution=storage_distribution(fs)
    return render_template('dashboard.html',files=fs,used=used,quota=current_app.config['USER_QUOTA_BYTES'],shares=ShareLink.query.filter_by(owner_id=current_user.id,revoked=False).count(),activities=ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(8).all(),distribution=distribution,folders=Folder.query.filter_by(owner_id=current_user.id,deleted_at=None).all())
def storage_distribution(files):
    total=sum(f.size for f in files); buckets={}
    for f in files:
        label=category(f.name); item=buckets.setdefault(label,{'name':label,'count':0,'bytes':0}); item['count']+=1; item['bytes']+=f.size
    return sorted([dict(v,percent=round(v['bytes']*100/total,1) if total else 0) for v in buckets.values()],key=lambda x:x['bytes'],reverse=True)
@bp.route('/files')
@login_required
def files():
    q=request.args.get('q','').strip(); query=File.query.filter_by(owner_id=current_user.id,deleted_at=None)
    if q: query=query.filter(File.name.ilike('%'+q+'%'))
    fs=query.order_by(File.created_at.desc()).all(); kind=request.args.get('type','')
    if kind: fs=[f for f in fs if category(f.name)==kind]
    return render_template('files.html',files=fs,query=q,kind=kind,trash=False,folders=Folder.query.filter_by(owner_id=current_user.id,deleted_at=None).all())
@bp.route('/trash')
@login_required
def trash(): return render_template('files.html',files=File.query.filter_by(owner_id=current_user.id).filter(File.deleted_at.is_not(None)).all(),query='',kind='',trash=True,folders=Folder.query.filter_by(owner_id=current_user.id).filter(Folder.deleted_at.is_not(None)).all())
@bp.route('/upload',methods=['POST'])
@login_required
@limiter.limit('30 per hour')
def upload():
    store=provider(current_app.config); used=sum(f.size for f in File.query.filter_by(owner_id=current_user.id,deleted_at=None).all())
    folder_id=request.form.get('folder_id','')
    target=resolve_folder(folder_id)
    for item in request.files.getlist('files'):
        name=secure_filename(item.filename or '')
        if not name or '.' not in name or name.rsplit('.',1)[1].lower() not in ALLOWED: flash(f'{name or "File"}: unsupported file type.','error'); continue
        raw=item.read()
        if not content_matches_extension(name,raw): flash(f'{name}: file content does not match its extension.','error'); continue
        digest=hashlib.sha256(raw).hexdigest(); dupe=File.query.filter_by(owner_id=current_user.id,sha256=digest,deleted_at=None).first()
        if dupe: flash(f'{name}: identical content exists as {dupe.name}.','error'); continue
        if used+len(raw)>current_app.config['USER_QUOTA_BYTES']: flash(f'{name}: quota exceeded.','error'); continue
        key,size,sha=store.put(BytesIO(raw)); f=File(owner_id=current_user.id,name=name,folder_id=target.id if target else None,size=size,storage_key=key,mime_type=mimetypes.guess_type(name)[0] or 'application/octet-stream',sha256=sha)
        db.session.add(f); db.session.commit(); log('upload',name,size); used+=size
    flash('Upload processing finished.','success'); return redirect(url_for('auth.folder_view',folder_id=target.id) if target else url_for('auth.files'))
def get_file(f,download=True):
    store=provider(current_app.config)
    try: content=store.read(f.storage_key)
    except FileNotFoundError: abort(404)
    if hashlib.sha256(content).hexdigest()!=f.sha256: abort(500)
    return current_app.response_class(content,mimetype=f.mime_type,headers={'Content-Disposition':('attachment' if download else 'inline')+'; filename="'+f.name+'"'})
@bp.route('/file/<int:file_id>/download')
@login_required
def download(file_id):
    f=owned(file_id); log('download',f.name,f.size); return get_file(f)
@bp.route('/file/<int:file_id>/preview')
@login_required
def preview(file_id): return get_file(owned(file_id),False)
@bp.route('/file/<int:file_id>/delete',methods=['POST'])
@login_required
def delete_file(file_id):
    f=owned(file_id); f.deleted_at=datetime.now(timezone.utc); db.session.commit(); log('delete',f.name); flash('Moved to trash.','success'); return redirect(url_for('auth.files'))
@bp.route('/file/<int:file_id>/restore',methods=['POST'])
@login_required
def restore(file_id):
    f=owned(file_id,True); f.deleted_at=None; db.session.commit(); log('restore',f.name); return redirect(url_for('auth.trash'))
@bp.route('/file/<int:file_id>/purge',methods=['POST'])
@login_required
def purge_file(file_id):
    f=owned(file_id,True)
    for link in ShareLink.query.filter_by(file_id=f.id).all(): db.session.delete(link)
    Favourite.query.filter_by(file_id=f.id).delete(synchronize_session=False)
    provider(current_app.config).delete(f.storage_key); name=f.name; db.session.delete(f); db.session.commit(); log('permanent_delete',name); flash('File permanently deleted.','success'); return redirect(url_for('auth.trash'))
@bp.route('/folder/<int:folder_id>/restore',methods=['POST'])
@login_required
def restore_folder(folder_id):
    folder=owned_folder(folder_id,True); folder.deleted_at=None; db.session.commit(); flash('Folder restored.','success'); return redirect(url_for('auth.trash'))
@bp.route('/folder/<int:folder_id>/purge',methods=['POST'])
@login_required
def purge_folder(folder_id):
    folder=owned_folder(folder_id,True)
    if File.query.filter_by(owner_id=current_user.id,folder_id=folder.id).count() or Folder.query.filter_by(owner_id=current_user.id,parent_id=folder.id).count():
        flash('A folder with contents cannot be permanently deleted.','error')
    else: db.session.delete(folder); db.session.commit(); flash('Folder permanently deleted.','success')
    return redirect(url_for('auth.trash'))
@bp.route('/trash/empty',methods=['POST'])
@login_required
def empty_trash():
    items=File.query.filter_by(owner_id=current_user.id).filter(File.deleted_at.is_not(None)).all(); store=provider(current_app.config)
    for f in items:
        for link in ShareLink.query.filter_by(file_id=f.id).all(): db.session.delete(link)
        Favourite.query.filter_by(file_id=f.id).delete(synchronize_session=False)
        store.delete(f.storage_key); db.session.delete(f)
    while True:
        folders=Folder.query.filter_by(owner_id=current_user.id).filter(Folder.deleted_at.is_not(None)).all(); leaves=[]
        for folder in folders:
            if not File.query.filter_by(owner_id=current_user.id,folder_id=folder.id).count() and not Folder.query.filter_by(owner_id=current_user.id,parent_id=folder.id).count(): leaves.append(folder)
        if not leaves: break
        for folder in leaves: db.session.delete(folder)
    db.session.commit(); flash('Trash permanently cleared.','success'); return redirect(url_for('auth.trash'))
@bp.route('/file/<int:file_id>/favorite',methods=['POST'])
@login_required
def favorite(file_id):
    f=owned(file_id); f.is_favorite=not f.is_favorite; db.session.commit(); return redirect(url_for('auth.files'))
@bp.route('/file/<int:file_id>/rename',methods=['POST'])
@login_required
def rename_file(file_id):
    f=owned(file_id); new_name=secure_filename(request.form.get('name','').strip())
    if not new_name or len(new_name)>255 or not content_matches_extension(new_name,provider(current_app.config).read(f.storage_key)):
        flash('Choose a safe name with an extension matching the file content.','error')
    else:
        f.name=new_name; f.mime_type=mimetypes.guess_type(new_name)[0] or 'application/octet-stream'; db.session.commit(); flash('File renamed.','success')
    return redirect(url_for('auth.files'))
@bp.route('/file/<int:file_id>/move',methods=['POST'])
@login_required
def move_file(file_id):
    f=owned(file_id); target=request.form.get('folder_id',''); folder=resolve_folder(target)
    f.folder_id=folder.id if folder else None; db.session.commit(); flash('File moved.','success')
    return redirect(url_for('auth.folder_view',folder_id=folder.id) if folder else url_for('auth.files'))
@bp.route('/favorites')
@login_required
def favorites(): return render_template('files.html',files=File.query.filter_by(owner_id=current_user.id,is_favorite=True,deleted_at=None).all(),query='',kind='',trash=False)
@bp.route('/folders',methods=['GET','POST'])
@login_required
def folders():
    if request.method=='POST':
        name=request.form.get('name','').strip(); parent=request.form.get('parent_id',''); parent_folder=resolve_folder(parent)
        if name and len(name)<=120: db.session.add(Folder(owner_id=current_user.id,name=name,parent_id=parent_folder.id if parent_folder else None)); db.session.commit(); log('folder_create',name); flash('Folder created.','success')
        else: flash('Folder name must be 1–120 characters.','error')
        return redirect(url_for('auth.folders'))
    roots=Folder.query.filter_by(owner_id=current_user.id,parent_id=None,deleted_at=None).all(); all_folders=Folder.query.filter_by(owner_id=current_user.id,deleted_at=None).all()
    valid_targets={f.id:[x for x in all_folders if x.id!=f.id and not folder_descends_from(x.id,f.id)] for f in roots}
    return render_template('folders.html',folders=roots,parent=None,all_folders=all_folders,valid_folder_targets=valid_targets)
@bp.route('/folders/<int:folder_id>')
@login_required
def folder_view(folder_id):
    folder=owned_folder(folder_id); children=Folder.query.filter_by(owner_id=current_user.id,parent_id=folder.id,deleted_at=None).all()
    fs=File.query.filter_by(owner_id=current_user.id,folder_id=folder.id,deleted_at=None).order_by(File.name).all()
    ancestors=[]; node=folder
    while node:
        ancestors.append(node); node=db.session.get(Folder,node.parent_id) if node.parent_id else None
    all_folders=Folder.query.filter_by(owner_id=current_user.id,deleted_at=None).all()
    valid_targets={f.id:[x for x in all_folders if x.id!=f.id and not folder_descends_from(x.id,f.id)] for f in children}
    return render_template('folders.html',folders=children,parent=folder,files=fs,all_folders=all_folders,valid_folder_targets=valid_targets,ancestors=list(reversed(ancestors)))
@bp.route('/folder/<int:folder_id>/rename',methods=['POST'])
@login_required
def rename_folder(folder_id):
    folder=owned_folder(folder_id); name=request.form.get('name','').strip()
    if not name or len(name)>120: flash('Folder name must be 1–120 characters.','error')
    else: folder.name=name; db.session.commit(); flash('Folder renamed.','success')
    return redirect(url_for('auth.folder_view',folder_id=folder.id) if folder.parent_id else url_for('auth.folders'))
@bp.route('/folder/<int:folder_id>/move',methods=['POST'])
@login_required
def move_folder(folder_id):
    folder=owned_folder(folder_id); target=request.form.get('parent_id','')
    parent=resolve_folder(target)
    if parent and (parent.id==folder.id or folder_descends_from(parent.id,folder.id)): abort(400)
    folder.parent_id=parent.id if parent else None; db.session.commit(); flash('Folder moved.','success')
    return redirect(url_for('auth.folder_view',folder_id=parent.id) if parent else url_for('auth.folders'))
@bp.route('/folder/<int:folder_id>/delete',methods=['POST'])
@login_required
def delete_folder(folder_id):
    folder=owned_folder(folder_id)
    if File.query.filter_by(owner_id=current_user.id,folder_id=folder.id,deleted_at=None).count() or Folder.query.filter_by(owner_id=current_user.id,parent_id=folder.id,deleted_at=None).count():
        flash('Move or delete the folder contents before deleting this folder.','error')
    else: folder.deleted_at=datetime.now(timezone.utc); db.session.commit(); flash('Folder moved to trash.','success')
    return redirect(url_for('auth.folders'))
@bp.route('/share/<int:file_id>',methods=['POST'])
@login_required
def share(file_id):
    f=owned(file_id); token=secrets.token_urlsafe(32); days=request.form.get('days',''); limit=request.form.get('limit',''); pw=request.form.get('password','')
    email=request.form.get('recipient_email','').strip().lower(); recipient=User.query.filter_by(email=email).first() if email else None
    if email and not recipient: flash('No CloudLock account exists for that email.','error'); return redirect(url_for('auth.files'))
    if recipient and recipient.id==current_user.id: flash('Choose a different recipient account.','error'); return redirect(url_for('auth.files'))
    if days and (not days.isdigit() or not 1<=int(days)<=365): flash('Expiry must be between 1 and 365 days.','error'); return redirect(url_for('auth.files'))
    if limit and (not limit.isdigit() or not 1<=int(limit)<=10000): flash('Download limit must be between 1 and 10000.','error'); return redirect(url_for('auth.files'))
    exp=datetime.now(timezone.utc)+timedelta(days=int(days)) if days else None
    link=ShareLink(file_id=f.id,owner_id=current_user.id,recipient_id=recipient.id if recipient else None,token_hash=hashlib.sha256(token.encode()).hexdigest(),password_hash=generate_password_hash(pw) if pw else None,allow_download=bool(request.form.get('download')),expires_at=exp,download_limit=int(limit) if limit.isdigit() and int(limit)>0 else None)
    db.session.add(link)
    if recipient: db.session.add(Notification(user_id=recipient.id,message=f'{current_user.name} shared {f.name} with you.'))
    db.session.commit(); log('share',f.name); flash(('Shared with '+recipient.name+'. ' if recipient else '')+'Share link: '+url_for('auth.public_share',token=token),'success'); return redirect(url_for('auth.shared'))
@bp.route('/shared')
@login_required
def shared(): return render_template('shared.html',links=ShareLink.query.filter_by(owner_id=current_user.id).order_by(ShareLink.created_at.desc()).all())
@bp.route('/shared-with-me')
@login_required
def shared_with_me():
    items=ShareLink.query.filter_by(recipient_id=current_user.id,revoked=False).order_by(ShareLink.created_at.desc()).all()
    now=datetime.now(timezone.utc)
    items=[s for s in items if (not s.expires_at or s.expires_at.replace(tzinfo=timezone.utc)>now) and (not s.download_limit or s.download_count<s.download_limit) and s.file and not s.file.deleted_at]
    return render_template('shared_with_me.html',links=items)
@bp.route('/shared-with-me/<int:share_id>',methods=['GET','POST'])
@login_required
def shared_with_me_open(share_id):
    s=ShareLink.query.filter_by(id=share_id,recipient_id=current_user.id,revoked=False).first_or_404(); now=datetime.now(timezone.utc)
    if s.expires_at and s.expires_at.replace(tzinfo=timezone.utc)<=now: abort(404)
    if s.download_limit and s.download_count>=s.download_limit: abort(404)
    unlocked=not s.password_hash or session.get(f'share_access_{s.id}',False)
    if request.method=='POST' and s.password_hash and check_password_hash(s.password_hash,request.form.get('password','')):
        session[f'share_access_{s.id}']=True; unlocked=True
    if not unlocked: return render_template('shared_with_me_open.html',share=s,bad=request.method=='POST',unlocked=False)
    return render_template('shared_with_me_open.html',share=s,bad=False,unlocked=True)
@bp.route('/shared-with-me/<int:share_id>/download')
@login_required
def shared_download(share_id):
    s=ShareLink.query.filter_by(id=share_id,recipient_id=current_user.id,revoked=False).first_or_404(); now=datetime.now(timezone.utc)
    if s.expires_at and s.expires_at.replace(tzinfo=timezone.utc)<=now: abort(404)
    if not s.allow_download: abort(403)
    if s.download_limit and s.download_count>=s.download_limit: abort(404)
    if s.password_hash and not session.get(f'share_access_{s.id}',False): return redirect(url_for('auth.shared_with_me_open',share_id=s.id))
    if not s.file or s.file.deleted_at: abort(404)
    reserve_share_download(s); log('shared_download',s.file.name,s.file.size); return get_file(s.file)
@bp.route('/shared-with-me/<int:share_id>/preview')
@login_required
def shared_preview(share_id):
    s=ShareLink.query.filter_by(id=share_id,recipient_id=current_user.id,revoked=False).first_or_404()
    if s.password_hash and not session.get(f'share_access_{s.id}',False): return redirect(url_for('auth.shared_with_me_open',share_id=s.id))
    if not s.file or s.file.deleted_at: abort(404)
    return get_file(s.file,False)
@bp.route('/share/revoke/<int:share_id>',methods=['POST'])
@login_required
def revoke(share_id):
    s=ShareLink.query.filter_by(id=share_id,owner_id=current_user.id).first_or_404(); s.revoked=True; db.session.commit(); log('share_revoke',str(share_id)); return redirect(url_for('auth.shared'))
@bp.route('/s/<token>',methods=['GET','POST'])
@limiter.limit('20 per minute')
def public_share(token):
    s=ShareLink.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first_or_404(); now=datetime.now(timezone.utc)
    if s.revoked or (s.expires_at and s.expires_at.replace(tzinfo=timezone.utc)<now) or (s.download_limit and s.download_count>=s.download_limit): abort(404)
    unlocked=not s.password_hash or session.get(f'share_access_{s.id}',False)
    if request.method=='POST' and s.password_hash and check_password_hash(s.password_hash,request.form.get('password','')):
        session[f'share_access_{s.id}']=True; unlocked=True
    if not unlocked: return render_template('public_share.html',link=s,bad=request.method=='POST',unlocked=False)
    f=db.session.get(File,s.file_id)
    if not f or f.deleted_at: abort(404)
    if request.args.get('view')=='1': return get_file(f,False)
    if request.args.get('download')=='1':
        if not s.allow_download: abort(403)
        reserve_share_download(s); return get_file(f)
    return render_template('public_share.html',link=s,bad=False,unlocked=True)
@bp.route('/activity')
@login_required
def activity(): return render_template('activity.html',activities=ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(100).all())
@bp.route('/analytics')
@login_required
def analytics():
    fs=File.query.filter_by(owner_id=current_user.id,deleted_at=None).all(); return render_template('analytics.html',files=fs,used=sum(f.size for f in fs),quota=current_app.config['USER_QUOTA_BYTES'],distribution=storage_distribution(fs))
@bp.route('/network')
def network(): return render_template('network.html')
@bp.route('/settings',methods=['GET','POST'])
@login_required
def settings():
    if request.method=='POST':
        current_user.name=request.form.get('name',current_user.name).strip()[:100]; pw=request.form.get('new_password','')
        if pw and (not current_user.check_password(request.form.get('current_password','')) or len(pw)<10): flash('Check current password and use a new password of 10+ characters.','error')
        elif pw: current_user.set_password(pw); flash('Profile and password updated.','success')
        else: flash('Profile updated.','success')
        db.session.commit(); return redirect(url_for('auth.settings'))
    return render_template('settings.html')
@bp.route('/api/network-events')
@login_required
def network_events():
    es=ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(20).all()
    return jsonify([{'method':e.method,'endpoint':e.endpoint,'status':e.status,'timestamp':e.created_at.isoformat(),'event':e.action,'transfer_bytes':e.transfer_size} for e in es])

