from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from models import db, User, Project
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ce258b349b3421173f5157dad2b4f815f791cb09c02cbf8dfd95eb2e5b3de592'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('editor'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash("Username already exists.")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(request.form['password'])
        new_user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registered successfully. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('editor'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/editor', methods=['GET', 'POST'])
@login_required
def editor():
    project = Project.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        html = request.form.get('html')
        css = request.form.get('css')
        js = request.form.get('js')
        if project:
            project.html_code = html
            project.css_code = css
            project.js_code = js
        else:
            project = Project(html_code=html, css_code=css, js_code=js, user_id=current_user.id)
            db.session.add(project)
        db.session.commit()
        flash("Code saved!")
    return render_template('editor.html', project=project)

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    project = Project.query.filter_by(user_id=user.id).first()
    return render_template('profile.html', user=user, project=project)

# Uncomment for debugging: Show all users (do not use in production)
'''
@app.route('/show_users')
def show_users():
    users = User.query.all()
    return '<br>'.join([f"{u.id}: {u.username}" for u in users])
'''

@app.route('/search')
def search():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify([])
    users = User.query.filter(User.username.ilike(f"%{query}%")).all()
    results = [{"id": user.id, "username": user.username} for user in users]
    return jsonify(results)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
