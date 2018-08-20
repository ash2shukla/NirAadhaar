from sqlalchemy import Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from time import time

from .config import DBPath

Base = declarative_base()

class LicenseKey(Base):
	__tablename__ = "LicenseKey"

	lk = Column(String(250),nullable=False)
	ts = Column(String,primary_key=True, default =int(time()))

def InitDB():
	engine = create_engine('sqlite:///'+DBPath)
	Base.metadata.create_all(engine)
