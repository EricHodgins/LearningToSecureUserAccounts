#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import re
import string
import hmac
import hashlib
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
							   autoescape=True)

#  Regular Expression Checks on username, password, e-mail

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r'^.{3,20}$')
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$') 
def valid_email(email):
	return not email or EMAIL_RE.match(email)

#  Securing Login with Hashing Functions

SECRET = 'imasecret'
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return s + "|" + hash_str(s)

def make_salt():
	return "".join([random.choice(string.letters) for i in xrange(5)])

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()

	hash_name_pw = hashlib.sha256(name+pw+salt).hexdigest()
	return hash_name_pw + "," + salt

def check_secure(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val


class MainHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class Users(db.Model):
	username = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	email = db.StringProperty(required=False)


class WelcomePage(MainHandler):
	def get(self):
		the_cookie = self.request.cookies.get('user_id')
		u_id = int(the_cookie.split('|')[0])
		user = Users.get_by_id(u_id)

		cookie_val = check_secure(the_cookie)
		if user and cookie_val:
			self.write("<br>Hello, %s" % user.username)
		else:
			self.redirect('/signup')


class Logout(MainHandler):
	def get(self):
		the_cookie = self.request.cookies.get('user_id')
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(""))
		self.redirect('/signup')



class LoginPage(MainHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')


		find_user = db.GqlQuery("SELECT * FROM Users WHERE username = :1 limit 1", username)
		user = find_user.get()
		user_id = user.key().id()
		if user != None:
			pwd = user.password
			salt = pwd.split(',')[1]

			if make_pw_hash(username, password, salt=salt) == pwd:
				secured_hash = make_secure_val(str(user_id))
				self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(secured_hash))
				self.redirect('/welcome')

		error_log = "Sorry, That's an invlid login."
		self.render("login.html", error_login=error_log)


class SignUpPage(MainHandler):
	def get(self):
		self.render("front.html")
		self.response.headers['Content-Type'] = 'text/html'


	def post(self):
		have_error = False

		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username=username,
					  email=email)

		if not valid_username(username):
			have_error = True
			params['error_username'] = "Looks like that's not a valid user name"

		if not valid_password(password):
			have_error = True
			params['error_password'] = "Not a valid password."
		elif password != verify:
			have_error = True
			params['error_verify'] = "You're passwords did not match."

		if not valid_email(email):
			have_error = True
			params['error_email'] = "Not a valid email."

		if have_error:
			self.render("front.html", **params)
		else:
			check_username = db.GqlQuery("SELECT * FROM Users WHERE username = :1 limit 1", username)
			if check_username.get() != None:
				params['error_username'] = "Sorry, that username already exists."
				self.render("front.html", **params)
				return 
			if check_username.get() == None:
				user_hash = make_pw_hash(username, password)
				
				p = Users(username=username, password=user_hash, email=email)
				p.put()
				secured_hash = make_secure_val(str(p.key().id()))
				self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(secured_hash))
				self.redirect("/welcome")


app = webapp2.WSGIApplication([
    ('/signup', SignUpPage),
    ('/welcome', WelcomePage),
    ('/login', LoginPage),
    ('/logout', Logout)
], debug=True)








