from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Role, UserActivity
from forms import LoginForm, RegistrationForm, UserForm, UserPermissionForm
from datetime import datetime
import logging
from functools import wraps

app = Blueprint('main', __name__)

# Thêm logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Vui lòng đăng nhập', 'warning')
            return redirect(url_for('main.login'))
            
        if not current_user.is_active:
            flash('Tài khoản đã bị vô hiệu hóa', 'danger')
            logout_user()
            return redirect(url_for('main.login'))
            
        if not current_user.role or current_user.role.role_name != 'Admin':
            flash('Không có quyền truy cập', 'danger')
            return redirect(url_for('main.index'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role.role_name == 'Admin':
            return redirect(url_for('main.admin_dashboard'))
        
        # Với user thường chỉ hiện thông tin cá nhân
        activities = UserActivity.query.filter_by(user_id=current_user.id)\
            .order_by(UserActivity.timestamp.desc())\
            .limit(10).all()
        
        return render_template('user_dashboard.html', activities=activities)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Nếu đã đăng nhập thì redirect
    if current_user.is_authenticated:
        if current_user.role.role_name == 'Admin':
            return redirect(url_for('main.admin_dashboard'))
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Log để debug
        print(f"Login attempt - Email: {form.email.data}")
        if user:
            print(f"User found - Role: {user.role.role_name}, Active: {user.is_active}")
        
        if not user:
            flash('Email hoặc mật khẩu không đúng', 'danger')
            return render_template('login.html', form=form)
            
        if not check_password_hash(user.password, form.password.data):
            flash('Email hoặc mật khẩu không đúng', 'danger')
            return render_template('login.html', form=form)
            
        if not user.is_active:
            flash('Tài khoản đã bị vô hiệu hóa', 'danger')
            return render_template('login.html', form=form)
        
        # Đăng nhập thành công
        login_user(user)
        user.last_login = datetime.utcnow()
        
        # Ghi log hoạt động
        activity = UserActivity(
            user_id=user.id,
            action='Login',
            description=f'User logged in from {request.remote_addr}',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            status='success'
        )
        
        try:
            db.session.add(activity)
            db.session.commit()
        except Exception as e:
            print(f"Error recording login activity: {str(e)}")
            db.session.rollback()
        
        # Redirect dựa trên role
        if user.role.role_name == 'Admin':
            print(f"Admin user logged in - Redirecting to admin dashboard")
            return redirect(url_for('main.admin_dashboard'))
            
        return redirect(url_for('main.index'))
        
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
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    
    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.name.ilike(f'%{search}%')
            )
        )
    
    users = query.paginate(page=page, per_page=10)
    return render_template('users.html', users=users, search=search)

@app.route('/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    try:
        if not current_user.role.role_name == 'Admin':
            return jsonify({'success': False, 'message': 'Không có quyền truy cập'}), 403
        
        user = User.query.get_or_404(id)
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'Không thể xóa chính mình'}), 400
        
        # Xóa activities trước
        UserActivity.query.filter_by(user_id=user.id).delete()
        
        activity = UserActivity(
            user_id=current_user.id,
            action='Delete User',
            description=f'Deleted user {user.username}'
        )
        
        db.session.add(activity)
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Xóa người dùng thành công'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin')
@login_required
@admin_required
def admin():
    return redirect(url_for('main.admin_dashboard'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    try:
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
                            
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        flash('Có lỗi xảy ra khi tải dữ liệu', 'danger')
        return redirect(url_for('main.index'))

@app.route('/roles')
@app.route('/admin/roles')
@login_required
@admin_required
def admin_roles():
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles', methods=['POST'])
@login_required
@admin_required
def add_role():
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
@admin_required
def get_role(id):
    role = Role.query.get_or_404(id)
    return {'id': role.id, 'role_name': role.role_name}

@app.route('/admin/roles/<int:id>', methods=['PUT'])
@login_required
@admin_required
def update_role(id):
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
@admin_required
def delete_role(id):
    role = Role.query.get_or_404(id)
    if role.users:
        return {'success': False, 'message': 'Không thể xóa quyền đang được sử dụng'}, 400
    
    db.session.delete(role)
    db.session.commit()
    return {'success': True}

@app.route('/admin/users/<int:id>/permissions', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_user_permissions(id):
    user = User.query.get_or_404(id)
    form = UserPermissionForm()
    form.role.choices = [(r.id, r.role_name) for r in Role.query.all()]
    
    if form.validate_on_submit():
        user.role_id = form.role.data
        user.permissions = {'allowed': form.permissions.data}
        
        activity = UserActivity(
            user_id=current_user.id,
            action='Update Permissions',
            description=f'Updated permissions for user {user.username}'
        )
        
        db.session.add(activity)
        db.session.commit()
        flash('Cập nhật quyền thành công', 'success')
        return redirect(url_for('main.users'))
        
    form.role.data = user.role_id
    form.permissions.data = user.permissions.get('allowed', [])
    return render_template('admin/user_permissions.html', form=form, user=user)

@app.route('/users/<int:id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(id):
    if not current_user.role.role_name == 'Admin':
        return jsonify({'success': False, 'message': 'Không có quyền thực hiện'})
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Không thể thay đổi trạng thái của chính mình'})
    
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True})

@app.route('/users/<int:id>/details')
@login_required
def get_user_details(id):
    user = User.query.get_or_404(id)
    return jsonify({
        'username': user.username,
        'email': user.email,
        'phone': user.phone or 'Chưa cập nhật',
        'address': user.address or 'Chưa cập nhật',
        'created_at': user.created_at.strftime('%d/%m/%Y'),
        'last_login': user.last_login.strftime('%d/%m/%Y %H:%M') if user.last_login else 'Chưa đăng nhập',
        'role': user.role.role_name
    })

@app.route('/activity-log')
@login_required
def activity_log():
    activities = UserActivity.query.filter_by(user_id=current_user.id)\
        .order_by(UserActivity.timestamp.desc()).all()
    return render_template('activity_log.html', activities=activities)

@app.route('/debug-info')
@login_required
def debug_info():
    if not current_user.role.role_name == 'Admin':
        return jsonify({'error': 'Not authorized'})
    
    return jsonify({
        'user_id': current_user.id,
        'email': current_user.email,
        'role': current_user.role.role_name,
        'is_active': current_user.is_active,
        'is_authenticated': current_user.is_authenticated
    })

@app.route('/auth-status')
def auth_status():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': current_user.id,
                'email': current_user.email,
                'role': current_user.role.role_name,
                'is_active': current_user.is_active
            }
        })
    return jsonify({
        'authenticated': False
    })

@app.route('/roles')
@login_required
@admin_required
def roles():
    roles = Role.query.all()
    return render_template('roles.html', roles=roles)