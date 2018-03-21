from flask import Flask,render_template,flash,request,redirect,url_for,session,jsonify

from flask_login import LoginManager,login_user, login_required, logout_user,current_user

from mongodb import mongo

from bson import json_util

from werkzeug.security import check_password_hash,generate_password_hash

import secrets

from datetime import timedelta

app=Flask(__name__)

app.secret_key = "super secret key"

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
user_record=mongo()


class User():
	def __init__(self, username):
		self.username = username
	def is_authenticated(self):
		return True
	def is_active(self):
		return True
	def is_anonymous(self):
		return False
	def get_id(self):
		return self.username


@app.route('/')
@app.route('/home')
def homepage():
	return render_template('home.html')


"""@app.route('/homepage')
def homepage():
	return render_template('home.html')
"""


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)


@app.route('/dashboard/')
@login_required
def dashboard():
	j=user_record.find_one({"username":session['username']})
	key=j['apikey']
	posts=j['post']
	return render_template('dashboard.html',posts=posts,key=key)


@login_manager.user_loader
def load_user(username):
    return User(username)


@app.route('/logout/')
@login_required
def logout():  
    logout_user()
    session['username']=None
    return redirect(url_for('homepage'))


@app.errorhandler(401)
def page_not_found(e):
    return render_template('401.html'), 401


@app.route('/login/', methods=['GET','POST'])
def login():
	error=None
	if request.method=='POST' and current_user.is_authenticated==False:
		username=request.form.get('username')
		password=request.form.get('password')

		if user_record.find_one({"username":username}):
			d=user_record.find_one({"username":username})
			p=d['password']
			if check_password_hash(p,password):
				user_obj = User(username)
				session['username']=username
				login_user(user_obj)
				flash('You are sucessfully logged in')
				return redirect(url_for('dashboard'))
		else:
			error="Invalid Credentials Try Again...."
			return render_template('signin.html',error=error)
	elif request.method=='POST' and current_user.is_authenticated==True:
		flash('You are already logged in')
		return redirect(url_for('dashboard'))
	return render_template('signin.html' ,error=error)


@app.route('/signup/', methods=['GET','POST'])
def signup():
	if request.method=='POST':
		username=request.form.get('username')
		if user_record.find_one({"username": username}):
			flash("Username Already Exist..Please Try A Different Username")
			return render_template("signup.html")
		else:
			user_obj = User(request.form.get('username'))
			login_user(user_obj)
			use={}
			use['username']=request.form.get('username')
			use['password']=generate_password_hash(request.form.get('password'),method='pbkdf2:sha256', salt_length=15)
			use['email']=request.form.get('email')
			use['apikey']=secrets.token_hex(30)
			use['post']=[]
			session['username']=username
			user_record.insert_one(use)
			flash('You are sucessfully logged in')
			return redirect(url_for('dashboard'))
	return render_template("signup.html")


@app.route('/allblog/')
@login_required
def allblog():
	userdata=user_record.find()
	l=[]
	for us in userdata:
		if us['username']==session['username']:
			pass
		else:
			posts=us['post']
			for post in posts:
				l.append(post)

	return render_template('allblog.html',posts=l)


@app.route('/userblog',methods=['GET','POST'])
@login_required
def userblog():
	if request.method=='POST':
		s={}
		s['title']=request.form.get('title')
		s['subtitle']=request.form.get('stitle')
		s['author']=request.form.get('author')
		s['blogtext']='</br>'.join(request.form.get('blog').split('\n'))
		j=user_record.find_one({"username":session['username']})
		j['post'].append(s)
		user_record.update_one({"username":session["username"]},{"$set":j})
		return redirect(url_for('dashboard'))
	elif request.method=='GET':
		return render_template('write.html')


@app.route('/usersdata/<path:data>')
@login_required
def usersdata(data):
	userdata=user_record.find()
	for us in userdata:
		if us['username']==session['username']:
			pass
		else:
			posts=us['post']
			for post in posts:
				if data==post['title']:
					datas=post['blogtext']
					break
	return render_template('singlepost.html',d=datas)


@app.route('/singlepage/<path:data>')
@login_required
def singlepage(data):
	user=user_record.find_one({"username":session['username']})
	for post in user['post']:
		if data==post['title']:
			datas=post['blogtext']
			break
	return render_template('singlepost.html',d=datas)


@app.route('/api')
def api():
	return render_template('api.html')

@app.route('/api/getallpost/')
def all():
	userdata=list(user_record.find())
	l=[]
	for us in userdata:
		posts=us['post']
		for post in posts:
			l.append(post)
	return json_util.dumps(l)


@app.route('/api/blog/',methods=['GET','DELETE','PATCH','POST'])
def requestwrite():
	if request.method=='GET':
		username=request.args.get('username')
		key=request.args.get('apikey')
		user=user_record.find_one({"username":username})
		if not user:
			return jsonify({"error":"no such username exists!!!"}),404
		if user['apikey']!=key:
			return jsonify({'error':'invalid key'})
		j=user['post']
		return json_util.dumps(j)

	elif request.method=='DELETE':
		k=0
		username=request.form.get('username')
		key=request.form.get('apikey')
		user=user_record.find_one({"username":username})
		if not user:
			return jsonify({"error":"no such username exists!!!"}),404
		if user['apikey']!=key:
			return jsonify({'error':'invalid key'})
		newpost=[]
		for post in user['post']:
			if post['title']==request.form.get('title'):
				k=1
				continue
			else:
				newpost.append(post)
		if k==0:
			return jsonify({'result':'No such article exists!!!'})
		user['post']=newpost
		user_record.update_one({"username":username},{"$set":user})
		return jsonify({"result":"sucessfully deleted user posts"})
		return jsonify({"result":"user post sucessfully deleted"})

	elif request.method=='PATCH':
		username=request.form.get('username')
		key=request.form.get('apikey')
		user=user_record.find_one({"username":username})
		if not user:
			return jsonify({"error":"no such username exists!!!"}),404
		if user['apikey']!=key:
			return jsonify({'error':'invalid key'})
		for post in user['post']:
			if post['title']==request.form.get('otitle'):
				post['title']=request.form.get('ntitle')
				post['subtitle']=request.form.get('subtitle')
				post['author']=request.form.get('author')
				post['blogtext']=request.form.get('blogtext')
				break
		else:
			return jsonify({'result':'No such article exists!!!'})
		user_record.update_one({"username":username},{"$set":user})
		return jsonify({"result":"sucessfully updated user posts"})
	
	elif request.method=='POST':
		username=request.form.get('username')
		print(username)
		key=request.form.get('apikey')
		user=user_record.find_one({"username":username})
		if not user:
			return jsonify({"error":"no such username exists!!!"}),404
		if user['apikey']!=key:
			return jsonify({'error':'invalid key'})
		s={}
		s['title']=request.form.get("title")
		s['subtitle']=request.form.get("subtitle")
		s['author']=request.form.get("author")
		s['blogtext']=request.form.get("blogtext")
		user['post'].append(s)
		user_record.update_one({"username":username},{"$set":user})
		return jsonify({"result":"sucessfully created data"})


@app.route('/delpos/<path:data>')
@login_required
def deletepost(data):
	username=session['username']
	user=user_record.find_one({"username":username})
	newpost=[]
	for post in user['post']:
		if post['title']==data:
			continue
		else:
			newpost.append(post)
	user['post']=newpost
	user_record.update_one({"username":username},{"$set":user})
	return redirect(url_for('dashboard'))


@app.route('/edit/<string:data>')
@login_required
def edit(data):
	username=session['username']
	user=user_record.find_one({"username":username})
	newdata=""
	for post in user['post']:
		if post['title']==data:
			newdata=post
			break
	return render_template('textedit.html',datas=newdata)


@app.route('/rewrite/<path:data>',methods=['POST'])
@login_required
def newdata(data):
	print('himanshu',data)
	username=session['username']
	user=user_record.find_one({"username":username})
	for post in user['post']:
		if post['title']==data:
			post['blogtext']='</br>'.join(request.form.get('blogtext').split('\n'))
			break
	user_record.update_one({"username":username},{"$set":user})
	return redirect(url_for('dashboard'))

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, post-check=0, pre-check=0"
    return response

#response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0') 

if __name__ == '__main__':
	app.run(port=8000,debug=True)