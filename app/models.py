from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from datetime import datetime

DATABASE_URL = "sqlite:///./test.db"

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    realname = Column(String)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Data(Base):
    __tablename__ = "data"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    realname = Column(String, index=True)
    date = Column(DateTime, default=datetime.utcnow)
    strong_index = Column(JSON)
    css = Column(JSON)



def init_db():
    Base.metadata.create_all(bind=engine)
