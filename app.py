from flask import Flask
from flask_login import LoginManager
from models import db, Role, User
from routes import app as routes_blueprint

app = Flask(__name__)

# Cấu hình
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://thien:thien2011@localhost/usermanagement'
app.config['SECRET_KEY'] = 'thien2011'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Khởi tạo extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Đăng ký Blueprint
app.register_blueprint(routes_blueprint)

# Khởi tạo database và dữ liệu mặc định
def init_db():
    with app.app_context():
        db.create_all()
        if not Role.query.first():
            roles = [
                Role(role_name='Admin'),
                Role(role_name='Content Manager'),
                Role(role_name='User')
            ]
            db.session.add_all(roles)
            try:
                db.session.commit()
                print("Đã khởi tạo roles mặc định thành công!")
            except Exception as e:
                db.session.rollback()
                print(f"Lỗi khi khởi tạo roles: {str(e)}")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)