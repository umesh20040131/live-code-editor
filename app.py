from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from models import db, User, Project, Friendship
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_

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
    # On POST, get project_id from form; on GET, from query string
    project_id = request.form.get('project_id') if request.method == 'POST' else request.args.get('project_id')
    if project_id:
        project = Project.query.filter_by(id=project_id, user_id=current_user.id).first()
    else:
        project = Project.query.filter_by(user_id=current_user.id).first()
    if not project:
        # Create a fresh project for new users
        project = Project(html_code='', css_code='', js_code='', user_id=current_user.id)
        db.session.add(project)
        db.session.commit()
    if request.method == 'POST':
        html = request.form.get('html')
        css = request.form.get('css')
        js = request.form.get('js')
        project.html_code = html
        project.css_code = css
        project.js_code = js
        db.session.commit()
        flash("Code saved!")
    return render_template('editor.html', project=project)

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    project = Project.query.filter_by(user_id=user.id).first()
    friendship = None
    if user.id != current_user.id:
        friendship = Friendship.query.filter(
            or_(
                and_(Friendship.requester_id == current_user.id, Friendship.receiver_id == user.id),
                and_(Friendship.requester_id == user.id, Friendship.receiver_id == current_user.id)
            )
        ).first()
    # Get all accepted friends for this user
    friends = User.query.join(
        Friendship,
        or_(
            and_(Friendship.requester_id == user.id, Friendship.receiver_id == User.id),
            and_(Friendship.receiver_id == user.id, Friendship.requester_id == User.id)
        )
    ).filter(Friendship.status == 'accepted').all()
    return render_template('profile.html', user=user, project=project, friendship=friendship, friends=friends)

@app.route('/add_friend/<int:user_id>', methods=['POST'])
@login_required
def add_friend(user_id):
    if user_id == current_user.id:
        flash("You can't add yourself as a friend.")
        return redirect(url_for('profile', username=current_user.username))
    existing = Friendship.query.filter_by(requester_id=current_user.id, receiver_id=user_id).first()
    if existing:
        flash("Friend request already sent.")
    else:
        friendship = Friendship(requester_id=current_user.id, receiver_id=user_id, status='pending')
        db.session.add(friendship)
        db.session.commit()
        flash("Friend request sent!")
    return redirect(url_for('profile', username=User.query.get(user_id).username))

@app.route('/respond_friend/<int:friendship_id>/<action>', methods=['POST'])
@login_required
def respond_friend(friendship_id, action):
    friendship = Friendship.query.get_or_404(friendship_id)
    if friendship.receiver_id != current_user.id:
        flash("Not authorized.")
        return redirect(url_for('profile', username=current_user.username))
    if action == 'accept':
        friendship.status = 'accepted'
        flash("Friend request accepted!")
    elif action == 'reject':
        friendship.status = 'rejected'
        flash("Friend request rejected.")
    db.session.commit()
    return redirect(url_for('profile', username=current_user.username))

@app.route('/new_project', methods=['POST'])
@login_required
def new_project():
    project = Project(html_code='', css_code='', js_code='', user_id=current_user.id)
    db.session.add(project)
    db.session.commit()
    flash("New project created!")
    return redirect(url_for('editor', project_id=project.id))

@app.context_processor
def inject_friends_and_projects():
    friends = []
    projects = []
    if current_user.is_authenticated:
        friends = User.query.join(
            Friendship,
            or_(
                and_(Friendship.requester_id == current_user.id, Friendship.receiver_id == User.id),
                and_(Friendship.receiver_id == current_user.id, Friendship.requester_id == User.id)
            )
        ).filter(Friendship.status == 'accepted').all()
        projects = Project.query.filter_by(user_id=current_user.id).all()
    return dict(my_friends=friends, my_projects=projects)

# Uncomment for debugging: Show all users (do not use in production)

'''@app.route('/show_users')
def show_users():
    users = User.query.all()
    return '<br>'.join([f"{u.id}: {u.username}" for u in users])'''

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
