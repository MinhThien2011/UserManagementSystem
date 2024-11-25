from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Role, UserActivity
from forms import LoginForm, RegistrationForm, UserForm
from datetime import datetime

app = Blueprint('main', __name__)

@app.route('/')
def index():
    if current_user.is_authenticated:
        stats = {
            'total_users': User.query.count(),
            'new_users': User.query.filter(
                User.created_at >= datetime.utcnow().date()
            ).count(),
            'admin_count': User.query.join(Role).filter(Role.role_name == 'Admin').count()
        }
        return render_template('index.html', stats=stats)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            activity = UserActivity(
                user_id=user.id,
                action='Login',
                description=f'User logged in from {request.remote_addr}'
            )
            db.session.add(activity)
            db.session.commit()
            
            return redirect(url_for('main.index'))
        flash('Email hoặc mật khẩu không đúng', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user_role = Role.query.filter_by(role_name='User').first()
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            name=form.name.data,
            role_id=user_role.id
        )
        db.session.add(user)
        db.session.commit()
        flash('Đăng ký thành công!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    activity = UserActivity(
        user_id=current_user.id,
        action='Logout',
        description='User logged out'
    )
    db.session.add(activity)
    db.session.commit()
    
    logout_user()
    return redirect(url_for('main.index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UserForm(obj=current_user)
    if form.validate_on_submit():
        current_user.name = form.name.data
        if form.password.data:
            current_user.password = generate_password_hash(form.password.data)
        
        activity = UserActivity(
            user_id=current_user.id,
            action='Profile Update',
            description='Updated profile information'
        )
        
        db.session.add(activity)
        db.session.commit()
        flash('Cập nhật thông tin thành công!', 'success')
        return redirect(url_for('main.profile'))
    
    activities = UserActivity.query.filter_by(user_id=current_user.id)\
        .order_by(UserActivity.timestamp.desc()).limit(10).all()
    
    return render_template('profile.html', form=form, activities=activities)

@app.route('/users')
@login_required
def users():
    if not current_user.role.role_name in ['Admin', 'Content Manager']:
        flash('Không có quyền truy cập', 'danger')
        return redirect(url_for('main.index'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    if not current_user.role.role_name == 'Admin':
        return {'success': False, 'message': 'Không có quyền truy cập'}, 403
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        return {'success': False, 'message': 'Không thể xóa chính mình'}, 400
    
    activity = UserActivity(
        user_id=current_user.id,
        action='Delete User',
        description=f'Deleted user {user.username}'
    )
    
    db.session.delete(user)
    db.session.add(activity)
    db.session.commit()
    
    return {'success': True}

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.role.role_name == 'Admin':
        flash('Không có quyền truy cập', 'danger')
        return redirect(url_for('main.index'))
    
    stats = {
        'total_users': User.query.count(),
        'new_users': User.query.filter(
            User.created_at >= datetime.utcnow().date()
        ).count(),
        'admin_count': User.query.join(Role).filter(Role.role_name == 'Admin').count()
    }
    
    recent_activities = UserActivity.query\
        .order_by(UserActivity.timestamp.desc())\
        .limit(10)\
        .all()
    
    new_users = User.query\
        .order_by(User.created_at.desc())\
        .limit(5)\
        .all()
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_activities=recent_activities,
                         new_users=new_users)

@app.route('/admin/roles')
@login_required
def admin_roles():
    if not current_user.role.role_name == 'Admin':
        flash('Không có quyền truy cập', 'danger')
        return redirect(url_for('main.index'))
    
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles', methods=['POST'])
@login_required
def add_role():
    if not current_user.role.role_name == 'Admin':
        return {'success': False, 'message': 'Không có quyền truy cập'}, 403
    
    data = request.get_json()
    role = Role(role_name=data['role_name'])
    db.session.add(role)
    try:
        db.session.commit()
        return {'success': True}
    except:
        db.session.rollback()
        return {'success': False, 'message': 'Tên quyền đã tồn tại'}, 400

@app.route('/admin/roles/<int:id>', methods=['GET'])
@login_required
def get_role(id):
    if not current_user.role.role_name == 'Admin':
        return {'success': False, 'message': 'Không có quyền truy cập'}, 403
    
    role = Role.query.get_or_404(id)
    return {'id': role.id, 'role_name': role.role_name}

@app.route('/admin/roles/<int:id>', methods=['PUT'])
@login_required
def update_role(id):
    if not current_user.role.role_name == 'Admin':
        return {'success': False, 'message': 'Không có quyền truy cập'}, 403
    
    role = Role.query.get_or_404(id)
    data = request.get_json()
    role.role_name = data['role_name']
    try:
        db.session.commit()
        return {'success': True}
    except:
        db.session.rollback()
        return {'success': False, 'message': 'Tên quyền đã tồn tại'}, 400

@app.route('/admin/roles/<int:id>', methods=['DELETE'])
@login_required
def delete_role(id):
    if not current_user.role.role_name == 'Admin':
        return {'success': False, 'message': 'Không có quyền truy cập'}, 403
    
    role = Role.query.get_or_404(id)
    if role.users:
        return {'success': False, 'message': 'Không thể xóa quyền đang được sử dụng'}, 400
    
    db.session.delete(role)
    db.session.commit()
    return {'success': True}