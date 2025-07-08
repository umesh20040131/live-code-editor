from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200))


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    html_code = db.Column(db.Text)
    css_code = db.Column(db.Text)
    js_code = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
