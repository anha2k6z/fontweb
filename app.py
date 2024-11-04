from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

#khởi tạo tên database 
db_name='quanli.db'
#kết nối với database 
app.config['SECRET_KEY']='admin'
app.config['SQLALCHEMY_DATABASE_URI']= f'sqlite:///{db_name}'

#khởi tạo database
db = SQLAlchemy(app)
login_manager=LoginManager(app)
login_manager.login_view='login'

#tạo bảng cơ sở dữ liệu 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
def load_admin(user_id):
    return User.query.get(int(user_id))
#điều hướng đến trang chủ 
@app.route('/')
def home():
    return redirect(url_for('login'))
#sử lý data tạo tài khoản 
@app.route('/signup',methods=["GET","POST"])
def signup():
    if request.method=='POST':
        #lấy dự liệu từ form đăng kí khi người dùng nhập vào 
        username= request.form['gmail']
        password=request.form['password']
        password=generate_password_hash(request.form['password'])
        is_admin = request.form.get('is_admin') == 'on' 
        #kiểm tra uers của người dùng nhập vào đã có trong database 
        checkuser=User.query.filter_by(username=username).first()

        if checkuser: 
            flash('Tài khoản đã tồn tại ')
            return redirect(url_for('signup'))
        #tạo tài khoản nếu chưa có
        new_user= User(username=username, password=password,is_admin=is_admin)
        #thêm tài khoản vào database 
        db.session.add(new_user)
        db.session.commit()
        flash("Tạo tài khoản thành công")
        #chuyển đến font đăng nhập
        return redirect(url_for('login'))
    return render_template('signup.html')
@app.route('/login',methods=["GET","POST"])
#sử lý data đăng nhập
def login():
    if request.method=='POST':
        username = request.form['gmail']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('user'))
        flash('Tên đăng nhập hoặc mật khẩu không đúng!')
        return redirect(url_for('signup'))
    return render_template('login.html')
#trang admin
@app.route('/admin')
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('user'))
    return render_template('admin.html')
#trang người dùng 
@app.route('/user')
def user():
    return render_template('user.html')

if __name__ == '__main__':
    #truy cập vào database
    with app.app_context():
        db.create_all()  # Tạo cơ sở dữ liệu
    app.run(debug=False) #run web


