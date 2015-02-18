import webapp2
import os
import jinja2
import re
import sys
import hashlib
import string
import random
import urllib2
import json
import logging
import time

from datetime import datetime
from xml.dom import minidom
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class RenderPage:
    @classmethod
    def render_table_header(cls):
        return render_str("tableHeader.html")


### Main Handler ###
class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = Accounts.make_hash_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s;Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and Accounts.check_hash_val(cookie_val)

    def login_set_cookie(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.query_by_id(int(uid))

### Accounts System ###
class Accounts:
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    @classmethod
    def valid_username(cls, username):
	 return cls.USER_RE.match(username)

    PASS_RE = re.compile(r"^.{3,20}$")
    @classmethod
    def valid_password(cls, password):
	 return cls.PASS_RE.match(password)

    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    @classmethod
    def valid_email(cls, email):
	 return cls.EMAIL_RE.match(email)

    COOKIE_RE = re.compile(r'.+=;\s*Path=/')
    @classmethod
    def valid_cookie(cls, cookie):
	return cookie and cls.COOKIE_RE.match(cookie)

    @classmethod
    def make_hash_val(cls, name):
	h = hashlib.sha256(name).hexdigest()
	return "%s|%s" %(name, h)

    @classmethod
    def check_hash_val(cls, hashed_val):
	x = hashed_val.split('|')[0]
	if  hashed_val == Accounts.make_hash_val(x):
            return x

    @classmethod
    def make_salt(cls):
	return ''.join([random.choice(string.letters) for x in xrange(5)])

    @classmethod
    def make_password(cls, name, pw, salt=None):
	if not salt:
	    salt = cls.make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" %(h, salt)

    @classmethod
    def valid_pw(cls, name, pw, h):
	salt = h.split('|')[1]
	return h == Accounts.make_password(name, pw, salt)

class SignupPage(WikiHandler):

    def get(self):
        #next_url = self.request.headers.get('referer', '/')
        self.render("signup.html")

    def post(self):

        has_fault = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        u = User.query_by_name(username)
        if u:
            self.render('signup.html', error_username="User already exists.")
            return
 
        params = dict(username = username, email = email)

        if not Accounts.valid_username(username):
            params['error_username'] = "Invalid Username"
            has_fault = True

        if not Accounts.valid_password(password):
            params['error_password'] = "Invalid Password"
            has_fault = True
        elif verify != password:
            params['error_verify'] = "Passwords Mismatch"
            has_fault = True

        if email and not Accounts.valid_email(email):
            params['error_email'] = "Invalid email"
            has_fault = True

        if has_fault:
            self.render("signup.html", **params)
        else:
            u = User.registerUser(username, password, email)
            u.put()

            self.login_set_cookie(u)
            self.redirect('/')

class LoginPage(WikiHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render("login.html", next_url=next_url)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        next_url = self.request.get("next_url")
        valid_login = False

        u = User.getUser(username, password)

        if not u:
            self.render("login.html", error_message="Invalid Login") 
        else:
            self.login_set_cookie(u)
            self.redirect('/')
            

class LogoutPage(WikiHandler):
    def get(self):
        self.set_cookie("user_id", "")
        self.redirect('/')

### User ###
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def users_key(cls, group = 'default'):
        return db.Key.from_path('users', group)


    @classmethod
    def query_by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def query_by_id(cls, uid):
        return User.get_by_id(uid, parent = User.users_key())
        
    
    @classmethod
    def getUser(cls, name, pw):
        u = cls.query_by_name(name) 
        if u and Accounts.valid_pw(name, pw, u.pw_hash):
            return u

    @classmethod
    def registerUser(cls, name, pw, email= None):
        return User(parent= User.users_key(), name=name, pw_hash=Accounts.make_password(name, pw), email=email)

### cache ###
#class cache:
    #@classmethod
    #def top_wikis(cls, update = False):
	#k1 = 'top'
	#k2 = 'time'
	#wikis = memcache.get(k1)
	#t = memcache.get(k2)
	#if wikis is none or update:
		#t = datetime.now()
		#wikis = db.gqlquery("select * "
					#"from wikientries "
					#"where ancestor is :1 "
					#"order by created desc "
					#"limit 10",
					#wikientries.wiki_key())
		#wikis = list(wikis)
		##logging.error("the len is %s", len(wikis))
		#memcache.set(k1, wikis)
		#memcache.set(k2, t)
	#return wikis, t


### wiki pages ###
class WikiEntries(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    lastModified=db.DateTimeProperty(auto_now=True)
    
    @staticmethod
    def wiki_key(path):
	return db.Key.from_path('/root' + path, "pages")

    @classmethod
    def query_by_path(cls, path):
        q = cls.all()
        q.ancestor(cls.wiki_key(path))
        q.order("-created")
        return q

    @classmethod
    def query_by_id(cls, vid, path):
        return WikiEntries.get_by_id(vid, parent = WikiEntries.wiki_key(path))

class EditPage(WikiHandler):
    def render_wiki(self, path, subject="", content="", error=""):
        vid = self.request.get("q")
        wikiEntry = None
        if vid:
            wikiEntry = WikiEntries.query_by_id(int(vid), path)
        if wikiEntry:
            subject = wikiEntry.subject
            content = wikiEntry.content
        self.render("wikiPost.html", subject=subject, content=content,  error=error)

    def get(self, path=""):
        if self.user:
            self.render_wiki(path)
        else:
            self.redirect("/login")

    def post(self, path=""):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if content:
            if not subject:
                subject = content[0:25]

            a = WikiEntries(parent=WikiEntries.wiki_key(path), subject=subject, content=content)
            a.put()

            self.redirect("%s" % path)
        else:
            error = "we need some wiki content!"
            self.render_wiki(error=error)

class WikiPage(WikiHandler):
    def render_wiki(self, path, error=""):
        wikiEntry = WikiEntries.query_by_path(path).get()
	if wikiEntry:
	    self.render("wikiEntry.html", error=error, wikiEntry=wikiEntry, path=path)
	else:
	    self.redirect('/_edit%s' % path)

    def get(self, path):
        self.render_wiki(path)

class HistoryPage(WikiHandler):
    def render_wiki(self, path, error=""):
        history = WikiEntries.query_by_path(path)
        history.fetch(limit = 100)
        entries = list(history)

        if entries:
            self.render("history.html", entries=entries, path=path)
        else:
            self.redirect('/_eidt' + path)

    def get(self, path):
        self.render_wiki(path)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([ (r'/.*signup', SignupPage), 
                            (r'/.*login', LoginPage),
                            ('/logout', LogoutPage), 
                            ('/_history' + PAGE_RE, HistoryPage), 
                            ('/_edit' + PAGE_RE, EditPage),
                            (PAGE_RE, WikiPage)],
                             debug=True)

