from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, IntegerField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User, Department, Role, Report, Comment, CEPReport, BSReport
from wtforms.ext.sqlalchemy.fields import QuerySelectField

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember_me = BooleanField('Remember Me')
	submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
	first_name = StringField('First Name', validators=[DataRequired()])
	last_name = StringField('Last Name', validators=[DataRequired()])
	username = StringField('Username', validators=[DataRequired()])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Register')

	def validate_username(self, username):
		user = User.query.filter_by(email=username.data).first()
		if user is not None:
			raise ValidationError('Please use a different username.')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is not None:
			raise ValidationError('Please use a different email address.')

class ResetPasswordRequestForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Request Password Reset')

class DepartmentForm(FlaskForm):
	name = StringField('Name', validators=[DataRequired()])
	description = StringField('Description', validators=[DataRequired()])
	submit = SubmitField('Submit')

class RoleForm(FlaskForm):
	name = StringField('Name', validators=[DataRequired()])
	description = StringField('Description', validators=[DataRequired()])
	submit = SubmitField('submit')

class UserAssignForm(FlaskForm):
	department = QuerySelectField(query_factory=lambda: Department.query.all(), get_label="name")
	role = QuerySelectField(query_factory=lambda: Role.query.all(), get_label="name")
	submit = SubmitField('submit')						

class ReportForm(FlaskForm):
	title = StringField('Report Title', validators=[DataRequired()])
	#CEP
	education = TextAreaField('Education')
	pss = TextAreaField('PSS')
	livelihood = TextAreaField('Livelihoods')
	spiritual = TextAreaField('Spiritual')
	numhomevisit = IntegerField('Number of Home visits')
	homevisit = TextAreaField('Home Visits')
	donorbond = TextAreaField('Sponsor/Donor Relationship')
	lifeskill = TextAreaField('Life skills')
	#Bible School
	numschool = IntegerField('Number of Schools operating')
	numstud = IntegerField('Number of Students')
	student = TextAreaField('List Students')
	numchurch = IntegerField('Number of Churches Planted')
	church = TextAreaField('List the churches planted')
	
	#Community Development
	igas = StringField('IGAs in Kayiriti carried out')
	numloanstaken = IntegerField('Loans taken')
	numloansback = IntegerField('Loans brought back')
	notesonloans = StringField('Notes on loans')

	#PWDs
	trainings = StringField('Trainings Carriedout')
	newentrants = StringField('New Entrants')
	salestracking = StringField('Sales Tracking')

	#CD, PWDs
	saving = StringField('Saving Schemes')
	dbspartnership = StringField('DBs partnerships')

	#DBs
	numdbs = IntegerField('Number of DBs')
	numnewdbs = IntegerField('Number of new DBs')
	newdbs = StringField('New DBs')
	attendance = StringField('Average attendance per week')
	schministries = StringField('School ministries done')
	otherministries = StringField('Other ministries/Service opportunities')

	#BS, CD, PWDs, DBs
	numfollowup = IntegerField('Number of followups done')
	notesfollowup = TextAreaField('Brief Notes on follow ups done')

	#orphanage
	security = StringField('Security of the Children')
	childdiet = StringField('Children Diet')
	childsanitation = StringField('Children Sanitation')
	childhealth = StringField('Children Health')
	#RM
	activities = StringField('Activities Carriedout')
	policies = StringField('Policies')
	implementation = StringField('Implementation')

	#Social Work
	numchild = IntegerField('Number of Children at the home')
	childphysicalhealth = StringField('Child Physical Health')
	resettlement = StringField('Resettlement')
	legalsupport = StringField('Legal Support')
	fostercare = StringField('Foster Care')


	#fields belonging to all departments
	achieved = TextAreaField('Achievements', validators=[DataRequired()])
	challenge = TextAreaField('Challenges', validators=[DataRequired()])
	othernote = TextAreaField('Other Notes', validators=[DataRequired()]) 

class CommentForm(FlaskForm):
	body = StringField('Body', validators=[DataRequired()])
	submit = SubmitField('Submit')
		
class  BSReportForm(FlaskForm):
	title = StringField('Report Title', validators=[DataRequired()])
	numschool = IntegerField('Number of Schools', validators = [DataRequired()])
	numstud = IntegerField('Number of Students', validators=[DataRequired()])
	student = TextAreaField('List Students', validators=[DataRequired()])
	numchurch = IntegerField('Number of Churches Planted', validators=[DataRequired()])
	church = TextAreaField('List the churches planted', validators=[DataRequired()])
	numfollowup = IntegerField('Number of followups done', validators=[DataRequired()])
	notesfollowup = TextAreaField('Brief Notes on follow ups done', validators=[DataRequired()])
	achieved = TextAreaField('Achievements', validators=[DataRequired()])
	challenge = TextAreaField('Challenges', validators=[DataRequired()])
	othernote = TextAreaField('Other Notes', validators=[DataRequired()]) 

class  CEPReportForm(FlaskForm):
	title = StringField('Report Title', validators=[DataRequired()])
	education = TextAreaField('Education', validators = [DataRequired()])
	pss = TextAreaField('PSS', validators=[DataRequired()])
	livelihood = TextAreaField('Livelihoods', validators=[DataRequired()])
	spiritual = TextAreaField('Spiritual', validators=[DataRequired()])
	homevisit = TextAreaField('Home Visits', validators=[DataRequired()])
	donorbond = TextAreaField('Sponsor/Donor Relationship', validators=[DataRequired()])
	lifeskill = TextAreaField('Life skills', validators=[DataRequired()])
	achieved = TextAreaField('Achievements', validators=[DataRequired()])
	challenge = TextAreaField('Challenges', validators=[DataRequired()])
	othernote = TextAreaField('Other Notes', validators=[DataRequired()]) 
	
