from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mật khẩu', validators=[DataRequired()])
    submit = SubmitField('Đăng nhập')

class RegistrationForm(FlaskForm):
    username = StringField('Tên đăng nhập', validators=[DataRequired(), Length(min=4, max=80)])
    name = StringField('Họ và tên', validators=[DataRequired(), Length(max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mật khẩu', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Xác nhận mật khẩu', 
        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Đăng ký')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Tên đăng nhập đã tồn tại')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email đã được đăng ký')

class UserForm(FlaskForm):
    name = StringField('Họ và tên', validators=[DataRequired(), Length(max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mật khẩu mới', validators=[Length(min=6)])
    confirm_password = PasswordField('Xác nhận mật khẩu mới', 
        validators=[EqualTo('password')])
    submit = SubmitField('Cập nhật')

class UserPermissionForm(FlaskForm):
    role = SelectField('Vai trò', coerce=int)
    permissions = SelectMultipleField('Quyền hạn', choices=[
        ('view_users', 'Xem danh sách người dùng'),
        ('edit_users', 'Chỉnh sửa người dùng'),
        ('delete_users', 'Xóa người dùng'),
        ('manage_roles', 'Quản lý vai trò')
    ])
    submit = SubmitField('Cập nhật')