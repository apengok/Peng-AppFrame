import os

basedir = os.path.abspath(os.path.dirname(__file__))

CSRF_ENABLED = True
SECRET_KEY = ' be a better man'

OPENID_PROVIDERS = [
        {'name':'Yahoo','url':'https://me.yahoo.com'},
        {'name': 'Google', 'url': 'https://www.google.com/accounts/o8/id'},
        {'name': 'AOL', 'url': 'http://openid.aol.com/<username>'},
        {'name': 'Flickr', 'url': 'http://www.flickr.com/<username>'},
        {'name': 'MyOpenID', 'url': 'https://www.myopenid.com'}
    ]

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir,'app.db')
#SQLALCHEMY_DATABASE_URI = 'mysql://username:password@myswlserver.local/quickhowto'
#SQLALCHEMY_DATABASE_URI = 'postgresql://scott:tiger@localhost:5432/myapp'
#SQLALCHEMY_ECHO = True
SQLALCHEMY_POLL_RECYCLE = 3

BABEL_DEFAULT_LOCAL = 'en'
BABEL_DEFAULT_FOLDER = 'translations'
LANGUAGES = {
        'en':{'flag':'gb','name':'English'},
        'zh':{'flag':'cn','name':'Chinese'},
        'pt': {'flag': 'pt', 'name': 'Portuguese'},
        'pt_BR': {'flag':'br', 'name': 'Pt Brazil'},
        'es': {'flag': 'es', 'name': 'Spanish'},
        'de': {'flag': 'de', 'name': 'German'},
        'ru': {'flag': 'ru', 'name': 'Russian'},
        'pl': {'flag': 'pl', 'name': 'Polish'},
        'ja_JP': {'flag': 'jp', 'name': 'Japanese'}
    }

#GLOBALS FOR GENERAL APP'S
UPLOAD_FOLDER = basedir + '/app/static/uploads/'
IMG_UPLOAD_FOLDER = basedir + '/app/static/uploads/'
IMG_UPLOAD_URI = '/static/uploads/'
AUTH_TYPE = 1
#AUTH_LDAP_SERVER = "ldap://dc.domain.net"
AUTH_ROLE_ADMIN = 'Admin'
AUTH_ROLE_PUBLIC = 'Public'
APP_NAME = "P.A.B.Example"
APP_THEME = "" #default
#APP_THEME = "cerulean.css"      # COOL
#APP_THEME = "amelia.css"
#APP_THEME = "cosmo.css"
#APP_THEME = "cyborg.css"       # COOL
#APP_THEME = "flatly.css"
#APP_THEME = "journal.css"
#APP_THEME = "readable.css"
#APP_THEME = "simplex.css"
#APP_THEME = "slate.css"          # COOL
#APP_THEME = "spacelab.css"      # NICE
#APP_THEME = "united.css"

