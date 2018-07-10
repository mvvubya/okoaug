from app import app, db, login
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import jwt
from time import time


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(80), index=True)
	last_name = db.Column(db.String(80), index=True)
	username = db.Column(db.String(64), index=True, unique=True)
	email = db.Column(db.String(120), index=True, unique=True)
	password_hash = db.Column(db.String(128))
	department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
	role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
	status_id = db.Column(db.Integer, db.ForeignKey('status.id'))
	is_admin = db.Column(db.Boolean, default=False)
	is_active = db.Column(db.Boolean, default=True)
	is_cep = db.Column(db.Boolean, default=True)
	report = db.relationship('Report', backref='author', lazy='dynamic')
	comment = db.relationship('Comment', backref='author', lazy='dynamic')


	def __repr__(self):
		return '<User {}>'.format(self.username)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)


	def get_reset_password_token(token):
		return jwt.encode({
			'reset_password': self.id, 'exp': time() + expires_in},
			app.config['SECRET_KEY'], algorithm='HS256').decode(utf-8)

	@staticmethod
	def verify_reset_password_token(token):
		try:
			id = jwt.decode(token, app.config['SECRET_KEY'],
				algorithms=['HS256'])['reset_password']
		except:
			return
		return User.query.get(id)

	def is_cep(self):
		return True

	def is_bibleschool(self):
		return True
			
@login.user_loader
def load_user(id):
	return User.query.get(int(id))


class Department(db.Model):
	"""
	Create a Department table
	"""
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60), unique=True)
	description = db.Column(db.String(200))
	user = db.relationship('User', backref='department',
                                lazy='dynamic')
	report = db.relationship('Report', backref='department',
                                lazy='dynamic')

	def __repr__(self):
		return '<Department: {}>'.format(self.name)

class Role(db.Model):
	"""
	Create a Role table
	"""
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60), unique=True)
	description = db.Column(db.String(200))
	user = db.relationship('User', backref='role',
                                lazy='dynamic')

	def __repr__(self):
		return '<Role: {}>'.format(self.name)

class Status(db.Model):
	"""
	Create Account Status table
	"""
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60), unique=True)
	description = db.Column(db.String(200))
	user = db.relationship('User', backref='status',
                                lazy='dynamic')

	def __repr__(self):
		return '<Status: {}>'.format(self.name)


class Report(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(60), index=True)
	#CEP
	education = db.Column(db.String(100))
	pss = db.Column(db.String(100))
	livelihood = db.Column(db.String(100))
	spiritual = db.Column(db.String(100))
	numhomevisit = db.Column(db.Integer)
	homevisit = db.Column(db.String(100))
	donorbond = db.Column(db.String(100))
	lifeskill = db.Column(db.String(100))

	#BS
	numschool = db.Column(db.Integer)
	numstud = db.Column(db.Integer)
	student = db.Column(db.String(100))
	numchurch = db.Column(db.Integer)
	church = db.Column(db.String(100))

	#Community Development
	igas = db.Column(db.String(100))
	numloanstaken = db.Column(db.Integer)
	numloansback = db.Column(db.Integer)
	notesonloans = db.Column(db.String(100))

	#PWDs
	trainings = db.Column(db.String(100))
	newentrants = db.Column(db.String(100))
	salestracking = db.Column(db.String(100))

	#CD, PWDs
	saving = db.Column(db.String(100))
	dbspartnership = db.Column(db.String(100))

	#DBs
	numdbs = db.Column(db.Integer)
	numnewdbs = db.Column(db.Integer)
	newdbs = db.Column(db.String(100))
	attendance = db.Column(db.String(100))
	schministries = db.Column(db.String(100))
	otherministries = db.Column(db.String(100))

	#BS, CD, PWDs, DBs
	numfollowup = db.Column(db.Integer)
	notesfollowup = db.Column(db.String(100))

	#orphanage
	security = db.Column(db.String(100))
	childdiet = db.Column(db.String(100))
	childsanitation = db.Column(db.String(100))
	childhealth = db.Column(db.String(100))
	#RM
	activities = db.Column(db.String(100))
	policies = db.Column(db.String(100))
	implementation = db.Column(db.String(100))

	#Social Work
	numchild = db.Column(db.Integer)
	childphysicalhealth = db.Column(db.String(100))
	resettlement = db.Column(db.String(100))
	legalsupport = db.Column(db.String(100))
	fostercare = db.Column(db.String(100))

	#all
	achieved = db.Column(db.String(100))
	challenge = db.Column(db.String(100))
	othernote = db.Column(db.String(100))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	comment = db.relationship('Comment', backref='title', lazy='dynamic')
	

	def __repr__(self):
		return '<Report {}>'.format(self.title, self.id)

class Comment(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	body = db.Column(db.String(140))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	report_id = db.Column(db.Integer, db.ForeignKey('report.id'))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	def __repr__(self):
		return '<Comment {}>'.format(self.body)
	
		

class BSReport(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(25), index=True)
	numschool = db.Column(db.Text)
	numstud = db.Column(db.Text)
	student = db.Column(db.String(60))
	numchurch = db.Column(db.String(60))
	church = db.Column(db.String(60))
	numfollowup = db.Column(db.String(60))
	notesfollowup = db.Column(db.String(60))
	achieved = db.Column(db.String(60))
	challenge = db.Column(db.String(60))
	othernote = db.Column(db.String(60))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)


	def __repr__(self):
		return '<BSReport {}>'.format(self.title)

class CEPReport(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(25), index=True)
	education = db.Column(db.String(60))
	pss = db.Column(db.String(60))
	livelihood = db.Column(db.String(60))
	spiritual = db.Column(db.String(60))
	homevisit = db.Column(db.String(60))
	donorbond = db.Column(db.String(60))
	lifeskill = db.Column(db.String(60))
	achieved = db.Column(db.String(60))
	challenge = db.Column(db.String(60))
	othernote = db.Column(db.String(60))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

	def __repr__(self):
		return '<CEPReport {}>'.format(self.body)
		