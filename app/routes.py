from app import app, db
from flask import render_template, flash, redirect, url_for, request
from app.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, DepartmentForm, RoleForm, UserAssignForm, ReportForm, CommentForm, CEPReportForm, BSReportForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Report, Department, Role, Comment
from werkzeug.urls import url_parse
from app.email import send_password_reset_email


@app.route('/')
@app.route('/index')
def index():
	return render_template('home/index.html', title='Home')


@app.route('/dashboard')
@login_required
def dashboard():
	return render_template('home/dashboard.html', title='Dashboard')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is None or not user.check_password(form.password.data):
			flash('Invalid username or password', 'danger')
			return redirect(url_for('login'))
		login_user(user, remember=form.remember_me.data)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('dashboard')
		return redirect(next_page)
	return render_template('login.html', title='Log In', form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(username=form.username.data, email=form.email.data, first_name = form.first_name.data, last_name = form.last_name.data,)
		user.set_password(form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('You have successfully registered! You can now login', 'success')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)

@app.route('/reset_password_request', methods=['GET','POST'])
def reset_password_request():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = ResetPasswordRequestForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user:
			send_password_reset_email(user)
		flash('Check your email for the instructions to reset your password', 'success')
		return redirect(url_for('login'))
	return render_template('reset_password_request.html', title='Reset Password', form = form)

@app.route('/reset_password/<token>', methods=['GET','POST'])
def reset_password(token):
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	user = User.verify_reset_password_token(token)
	if not user:
		return redirect(url_for('index'))
	form = ResetPasswordForm()
	if form.validate_on_submit():
		user.set_password(form.password.data)
		db.session.commit()
		flash('Your password has been reset.', 'success')
		return redirect(url_for('login'))
	return render_template('reset_password.html', form=form)


def check_admin():
	if not current_user.is_admin:
		abort(403)

@app.route('/departments', methods=['GET', 'POST'])
@login_required
def list_departments():
	check_admin()
	departments = Department.query.all()
	return render_template('admin/departments.html', title='Departments', departments=departments)

@app.route('/departments/add', methods=['GET', 'POST'])
@login_required
def add_department():
	check_admin()
	add_department = True
	form = DepartmentForm()
	if form.validate_on_submit():
		department = Department(name=form.name.data, description=form.description.data)
		try:
			db.session.add(department)
			db.session.commit()
			flash('You have successfully added a new department.', 'success')
		except:
			flash('Error: department name already exists.', 'danger')

		return redirect(url_for('list_departments'))

	return render_template('admin/department.html', action="Add", add_department=add_department, form=form, title='Add Department')

@app.route('/departments/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit_department(id):
	check_admin()
	add_department=False
	department = Department.query.get_or_404(id)
	form = DepartmentForm(obj=department)
	if form.validate_on_submit():
		department.name = form.name.data
		department.description = form.description.data
		db.session.commit()
		flash('You have successfully edited the department.', 'success')

		return redirect(url_for('list_departments'))

	form.description.data = department.description
	form.name.data = department.name
	return render_template('admin/department.html', action="Edit", title='Edit Department', add_department=add_department, form=form, department=department)

@app.route('/departments/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_department(id):
	check_admin()
	department = Department.query.get_or_404(id)
	db.session.delete(department)
	db.session.commit()
	flash('You have successfully deleted the department', 'success')

	return redirect(url_for('list_departments'))

	return render_template(title="Delete Department")


@app.route('/roles', methods=['GET','POST'])
@login_required
def list_roles():
	check_admin()
	roles = Role.query.all()
	return render_template('admin/roles.html', roles=roles, title='Roles')

@app.route('/roles/add', methods=['GET','POST'])
@login_required
def add_role():
	check_admin()
	add_role = True
	form = RoleForm()
	if form.validate_on_submit():
		role = Role(name=form.name.data, description=form.description.data)

		try:
			db.session.add(role)
			db.session.commit()
			flash('You have successfully added a new role', 'success')
		except:
			flash('Error: role name already exists.','danger')

		return redirect(url_for('list_roles'))
	return render_template('admin/role.html', add_role=add_role, form=form, title='Add Role')

@app.route('/roles/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit_role(id):
	check_admin()
	add_role = False
	role = Role.query.get_or_404(id)
	form = RoleForm(obj=role)
	if form.validate_on_submit():
		role.name = form.name.data
		role.description = form.description.data
		db.session.add(role)
		db.session.commit()
		flash('You have successfully edited the role','success')

		return redirect(url_for('list_roles'))

	form.description.data = role.description
	form.name.data = role.name
	return render_template('admin/role.html', add_role=add_role, form=form, title='Edit Role')

@app.route('/roles/delete/<int:id>', methods=['GET','POST'])
@login_required
def delete_role(id):
	check_admin()
	role = Role.query.get_or_404(id)
	db.session.delete(role)
	db.session.commit()
	flash('You have successfully deleted the role','success')

	return redirect(url_for('list_roles'))

	return render_template(title="Delete Role")

@app.route('/users', methods=['GET','POST'])
@login_required
def list_users():
	check_admin()
	users = User.query.all()
	return render_template('users/users.html', users = users, title='Users')

@app.route('/users/assign/<int:id>', methods=['GET','POST'])
@login_required
def assign_user(id):
	check_admin()
	user = User.query.get_or_404(id)
	if user.is_admin:
		abort(403)

	form = UserAssignForm(obj=user)
	if form.validate_on_submit():
		user.department = form.department.data

		user.role = form.role.data
		db.session.add(user)
		db.session.commit()
		flash('You have successfully assigned a department and a role.','success')

		return redirect(url_for('list_users'))

	return render_template('users/user.html', user = user, form=form, title='Assign User')

@app.route('/reports', methods=['GET','POST'])
@login_required
def list_reports():
	reports = Report.query.all()
	return render_template('reports.html', reports=reports, title='Reports')

@app.route('/report/add', methods=['GET', 'POST'])
@login_required
def add_report():
	add_report = True
	form = ReportForm()
	if form.validate_on_submit():
		report = Report(title=form.title.data, 
						#CEP
						education=form.education.data,
						pss = form.pss.data,
						livelihood = form.livelihood.data,
						spiritual = form.spiritual.data,
						numhomevisit = form.numhomevisit.data,
						homevisit = form.homevisit.data,
						donorbond = form.donorbond.data,
						lifeskill = form.lifeskill.data,
						#BS
						numschool = form.numschool.data,
						numstud = form.numstud.data,
						student = form.student.data,
						numchurch = form.numchurch.data,
						church = form.church.data,

						#Community Development
						igas = form.igas.data,
						numloanstaken = form.numloanstaken.data,
						numloansback = form.numloansback.data,
						notesonloans = form.notesonloans.data,

						#PWDs
						trainings = form.trainings.data,
						newentrants = form.newentrants.data,
						salestracking = form.salestracking.data,

						#CD, PWDs
						saving = form.saving.data,
						dbspartnership = form.dbspartnership.data,

						#DBs
						numdbs = form.numdbs.data,
						numnewdbs = form.numnewdbs.data,
						newdbs = form.newdbs.data,
						attendance = form.attendance.data,
						schministries = form.schministries.data,
						otherministries = form.otherministries.data,

						#BS, CD, PWDs, DBs
						numfollowup = form.numfollowup.data,
						notesfollowup = form.notesfollowup.data,
						
		                #orphanage
						security = form.security.data,
						childdiet = form.childdiet.data,
						childsanitation = form.childsanitation.data,
						childhealth = form.childhealth.data,
						#RM
						activities = form.activities.data,
						policies = form.policies.data,
						implementation = form.implementation.data,

						#Social Work
						numchild = form.numchild.data,
						childphysicalhealth = form.childphysicalhealth.data,
						resettlement = form.resettlement.data,
						legalsupport = form.legalsupport.data,
						fostercare = form.fostercare.data, 
		                
						#general fields
						achieved = form.achieved.data,
						challenge = form.challenge.data,
						othernote = form.othernote.data,
						department_id = current_user.department_id,
						user_id = current_user.id
						)
		db.session.add(report)
		db.session.commit()
		flash('Your report has succesfully been sent.','success')

		return redirect(url_for('list_reports'))

	return render_template('report.html', form = form, action="Add", add_report=add_report, title='Write Report')

@app.route('/reports/view/<int:id>', methods=['GET','POST'])
@login_required
def view_details(id):
	report = Report.query.get_or_404(id)

	form = CommentForm()
	if form.validate_on_submit():
		comment = Comment(body=form.body.data, report_id=report.id, user_id=current_user.id )
		db.session.add(comment)
		db.session.commit()
		flash('Your comment has been sent','success')

		return redirect(url_for('list_reports')) 

	return render_template('view_report.html', report = report, id=id, form=form, title='Report Details')

@app.route('/report/edit/<int:id>')
def edit_report(id):
	add_report = False
	report = Report.query.get_or_404(id)
	form = ReportForm(obj=report)
	if form.validate_on_submit():
		report.title=form.title.data 
		#CEP
		report.education=form.education.data
		report.pss = form.pss.data
		report.livelihood = form.livelihood.data
		report.spiritual = form.spiritual.data
		report.numhomevisit = form.numhomevisit.data
		report.homevisit = form.homevisit.data
		report.donorbond = form.donorbond.data
		report.lifeskill = form.lifeskill.data
		#BS
		report.numschool = form.numschool.data
		report.numstud = form.numstud.data
		report.student = form.student.data
		report.numchurch = form.numchurch.data
		report.church = form.church.data
		#Community Development
		report.igas = form.igas.data
		report.numloanstaken = form.numloanstaken.data
		report.numloansback = form.numloansback.data
		report.notesonloans = form.notesonloans.data
		#PWDs
		report.trainings = form.trainings.data
		report.newentrants = form.newentrants.data
		report.salestracking = form.salestracking.data
		#CD, PWDs
		report.saving = form.saving.data
		report.dbspartnership = form.dbspartnership.data
		#DBs
		report.numdbs = form.numdbs.data
		report.numnewdbs = form.numnewdbs.data
		report.newdbs = form.newdbs.data
		report.attendance = form.attendance.data
		report.schministries = form.schministries.data
		report.otherministries = form.otherministries.data
		#BS, CD, PWDs, DBs
		report.numfollowup = form.numfollowup.data
		report.notesfollowup = form.notesfollowup.data
		#orphanage
		report.security = form.security.data
		report.childdiet = form.childdiet.data
		report.childsanitation = form.childsanitation.data
		report.childhealth = form.childhealth.data
		#RM
		report.activities = form.activities.data
		report.policies = form.policies.data
		report.implementation = form.implementation.data
		#Social Work
		report.numchild = form.numchild.data,
		report.childphysicalhealth = form.childphysicalhealth.data
		report.resettlement = form.resettlement.data
		report.legalsupport = form.legalsupport.data
		report.fostercare = form.fostercare.data
		#general fields
		report.achieved = form.achieved.data
		report.challenge = form.challenge.data
		report.othernote = form.othernote.data
		db.session.add(report)
		db.session.commit()
		flash('You have successfully edited the report','success')

		return redirect(url_for('list_reports'))

	form.title.data = report.title 
	#CEP
	form.education.data = report.education
	form.pss.data =	report.pss  
	form.livelihood.data = report.livelihood
	form.spiritual.data = report.spiritual 
	form.numhomevisit.data = report.numhomevisit  
	form.homevisit.data = report.homevisit 
	form.donorbond.data = report.donorbond 
	form.lifeskill.data = report.lifeskill  
	#BS
	form.numschool.data = report.numschool  
	form.numstud.data = report.numstud  
	report.student = form.student.data
		
	return render_template('admin/report.html', add_report=add_report, form=form, title='Edit Report')



@app.route('/cepreport', methods=['GET', 'POST'])
@login_required
def cepreport():
	form = CEPReportForm()
	if form.validate_on_submit():
		cepreport = CEPReport(title=form.title.data, pss=form.pss.data, livelihood=form.livelihood.data, spiritual=form.spiritual.data, homevisit=form.homevisit.data, donorbond=form.donorbond.data, lifeskill=form.lifeskill.data, othernote=form.othernote.data, achieved=form.achieved.data, challenge=form.challenge.data, user_id=current_user)
		db.session.add(cepreport)
		db.session.commit()
		flash('Your report has been sent!', 'success')
		return redirect(url_for('index.html'))
	return render_template("cepreport.html", title='CEP Report', form=form)
