import os, secrets
from pathlib import Path
from flask import Flask, render_template
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///cloudvault.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH_MB", "100"))*1024*1024,
        STORAGE_BACKEND=os.getenv("STORAGE_BACKEND", "local").lower(),
        LOCAL_STORAGE_PATH=os.getenv("LOCAL_STORAGE_PATH", "uploads"),
        USER_QUOTA_BYTES=int(os.getenv("USER_QUOTA_MB", "1024"))*1024*1024,
        SUPABASE_URL=os.getenv("SUPABASE_URL", ""), SUPABASE_KEY=os.getenv("SUPABASE_KEY", ""),
        SUPABASE_BUCKET=os.getenv("SUPABASE_BUCKET", "cloudvault"),
        PASSWORD_RESET_LOG_LINKS=os.getenv("PASSWORD_RESET_LOG_LINKS", "false").lower()=="true",
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower()=="true",
        REMEMBER_COOKIE_HTTPONLY=True, REMEMBER_COOKIE_SAMESITE="Lax", DEBUG=False,
    )
    if test_config: app.config.update(test_config)
    if app.config['STORAGE_BACKEND']=='supabase' and not (app.config['SUPABASE_URL'] and app.config['SUPABASE_KEY']):
        app.logger.warning('Supabase credentials missing; using local development storage.')
        app.config['STORAGE_BACKEND']='local'
    elif app.config['STORAGE_BACKEND']=='supabase':
        from .storage import provider
        try: provider(app.config).validate_private_bucket()
        except Exception as exc: raise RuntimeError('Supabase storage was configured but its private bucket could not be verified.') from exc
    db.init_app(app); login_manager.init_app(app); csrf.init_app(app); limiter.init_app(app)
    login_manager.login_view='auth.login'
    login_manager.login_message='Please sign in to continue.'
    from .models import User
    @login_manager.user_loader
    def load_user(user_id): return db.session.get(User, int(user_id))
    from .routes import bp
    app.register_blueprint(bp)
    @app.errorhandler(404)
    def not_found(e): return render_template('error.html', code=404, message='That page could not be found.'),404
    @app.errorhandler(403)
    def forbidden(e): return render_template('error.html', code=403, message='You do not have access to this resource.'),403
    @app.errorhandler(413)
    def too_large(e): return render_template('error.html', code=413, message='That upload exceeds the configured size limit.'),413
    @app.errorhandler(500)
    def server_error(e): db.session.rollback(); return render_template('error.html', code=500, message='Something went wrong. Please try again.'),500
    with app.app_context():
        db.create_all()
        # Additive upgrade for databases created by earlier CloudLock versions.
        from sqlalchemy import inspect, text
        columns={column['name'] for column in inspect(db.engine).get_columns('share_link')}
        if 'recipient_id' not in columns:
            with db.engine.begin() as connection:
                connection.execute(text('ALTER TABLE share_link ADD COLUMN recipient_id INTEGER REFERENCES user(id)'))
        folder_columns={column['name'] for column in inspect(db.engine).get_columns('folder')}
        if 'deleted_at' not in folder_columns:
            with db.engine.begin() as connection:
                connection.execute(text('ALTER TABLE folder ADD COLUMN deleted_at DATETIME'))
        Path(app.config['LOCAL_STORAGE_PATH']).mkdir(parents=True, exist_ok=True)
    return app
