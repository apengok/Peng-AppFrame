import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'..','..','..')))
print os.path.abspath(os.path.join(os.path.dirname(__file__),'..','..','..'))

from flask import Flask

from flask_appbuilder import SQLA,AppBuilder

from sqlalchemy.engine import Engine
from sqlalchemy import event

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
logging.getLogger().setLevel(logging.DEBUG)


app = Flask(__name__)
app.config.from_object('config')
db = SQLA(app)
appbuilder = AppBuilder(app,db.session)

"""
#Only include this for SQLLite constraints

@event.listens_for(Engine,"connect")
def set_sqlite_pragma(dbapi_connection,connection_record):
    cursor = dbapi_connection.cursor()
    sursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
"""

from app import models,views

