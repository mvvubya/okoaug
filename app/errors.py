from flask import render_template
from app import app, db

@app.errorhandler(403)
def forbidden(error):
	return render_template('400.html', title='Fordidden'), 403

@app.errorhandler(404)
def not_found_error(error):
	return render_template('404.html', title='Not Found'), 404

@app.errorhandler(500)
def internal_error(error):
	db.session.rollback()
	return render_template('500.html', title='Server Error'), 500

