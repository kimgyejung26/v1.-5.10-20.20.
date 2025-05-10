# app.py

from flask import Flask, render_template, request, redirect, session, url_for
from models import db, User, FamilyMember
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db.init_app(app)

@app.route('/')
def home():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        userid = request.form['userid']
        name = request.form['name']
        password = request.form['password']

        existing_user = User.query.filter_by(userid=userid).first()
        if existing_user:
            return render_template('signup.html', error="이미 존재하는 아이디입니다.")

        hashed_pw = generate_password_hash(password)
        new_user = User(userid=userid, name=name, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid']
        pw = request.form['password']
        user = User.query.filter_by(userid=userid).first()
        if user and check_password_hash(user.password, pw):
            session['user'] = user.userid
            return redirect('/main')
        return render_template('login.html', error="아이디 또는 비밀번호가 일치하지 않습니다.")
    return render_template('login.html')

@app.route('/main')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template('main_page.html')

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')

    userid = session['user']
    user = User.query.filter_by(userid=userid).first()

    if not user:
        return "해당 유저를 찾을 수 없습니다.", 404

    return render_template('profile.html', user=user)

@app.route('/edit_family', methods=['GET', 'POST'])
def edit_family():
    if 'user' not in session:
        return redirect('/login')
    
    user = User.query.filter_by(userid=session['user']).first()

    if request.method == 'POST':
        for key in request.form:
            if key.endswith('_name'):
                member_id = key.split('_')[1]
                name = request.form.get(f'member_{member_id}_name')
                relation = request.form.get(f'member_{member_id}_relation')
                traits = request.form.get(f'member_{member_id}_traits')
                image = request.files.get(f'member_{member_id}_image')

                filename = None
                if image and image.filename:
                    filename = secure_filename(f"{session['user']}_{image.filename}")
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                new_member = FamilyMember(
                    user_id=user.id,
                    name=name,
                    relation=relation,
                    traits=traits,
                    image_filename=filename
                )
                db.session.add(new_member)
        db.session.commit()
        return redirect(url_for('edit_family'))

    family_members = FamilyMember.query.filter_by(user_id=user.id).all()
    return render_template('edit_family.html', family_members=family_members)

@app.route('/edit_family/<int:member_id>', methods=['POST'])
def update_family_member(member_id):
    if 'user' not in session:
        return redirect('/login')

    user = User.query.filter_by(userid=session['user']).first()
    member = FamilyMember.query.get(member_id)

    if member and member.user_id == user.id:
        member.name = request.form.get('name')
        member.relation = request.form.get('relation')
        member.traits = request.form.get('traits')

        image = request.files.get('image')
        if image and image.filename:
            filename = secure_filename(f"{session['user']}_{image.filename}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            member.image_filename = filename

        db.session.commit()

    return redirect(url_for('edit_family'))


@app.route('/delete_family/<int:member_id>', methods=['GET'])
def delete_family_member(member_id):
    if 'user' not in session:
        return redirect('/login')

    user = User.query.filter_by(userid=session['user']).first()
    member = FamilyMember.query.get(member_id)

    if member and member.user_id == user.id:
        db.session.delete(member)
        db.session.commit()

    return redirect(url_for('edit_family'))


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # 로그인 상태 제거 (세션 초기화)
    return redirect(url_for('login'))  # 로그인 화면으로 이동

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4040, debug=True)



'''
회원가입
from flask import Flask, render_template, request, redirect
app = Flask(__name__)
users = {}  # ID 중복 체크용 예시 (나중에 DB로 대체 가능)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        userid = request.form['userid']
        name = request.form['name']
        password = request.form['password']

        if userid in users:
            return render_template('signup.html', error="이미 존재하는 아이디입니다.")
        
        users[userid] = {'name': name, 'password': password}
        return redirect('/login')
    
    return render_template('signup.html')

로그인인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid']
        pw = request.form['password']
        # 실제 로그인 로직 (users는 딕셔너리 예시)
        if userid not in users or users[userid]['password'] != pw:
            return render_template('login.html', error="아이디 또는 비밀번호가 일치하지 않습니다.")
        session['user'] = userid
        return redirect('/dashboard')
    return render_template('login.html')

프로필필
from flask import Flask, render_template, session

app = Flask(__name__)
app.secret_key = "your_secret_key"  # 세션용

# 예시: 로그인된 사용자 정보
users = {
    "junyoung": {"name": "차준영", "userid": "junyoung", "password": "1234"}
}

@app.route("/profile")
def profile():
    # 로그인한 사용자 아이디를 세션에서 가져온다고 가정
    userid = session.get("user", "junyoung")  # 예시로 기본값 줌
    user = users.get(userid, {"name": "unknown", "userid": "none", "password": "****"})

    return render_template("profile.html", user=user)

메인화면
from flask import Flask, render_template

app = Flask(__name__)

# 메인 페이지 경로
@app.route('/')
def main():
    return render_template("main_page.html")

if __name__ == "__main__":
    app.run(debug=True)

가족 수정
@app.route('/edit_family', methods=['GET', 'POST'])
def edit_family():
    if request.method == 'POST':
        # form 데이터 처리
        name1 = request.form.get('class1_name')
        file1 = request.files.get('class1_img')
        # 저장 처리 등등...
        return redirect(url_for('edit_family'))

    return render_template('edit_family.html')

새사진 분석석
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/recognize')
def recognize():
    return render_template('face_recognition_view.html')

    
로그아웃
from flask import session, redirect, url_for

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # 로그인 상태 제거 (세션 초기화)
    return redirect(url_for('login'))  # 로그인 화면으로 이동

@app.route('/login')
def login():
    return render_template('login.html')

리마인더
@app.route('/reminder')
def show_reminder():
    return render_template("reminder.html")

'''