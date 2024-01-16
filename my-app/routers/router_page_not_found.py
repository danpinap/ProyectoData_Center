from app import app
from flask import request, session, redirect, url_for, render_template

@app.errorhandler(404)
def page_not_found(error):
    if 'conectado' in session:
        return render_template('public/error_page.html', message="La página que buscas no existe.")
    else:
        return redirect(url_for('inicio'))
