from sqlalchemy import Column, Boolean, VARCHAR
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class DBtable(Base):
    __tablename__ = "userInfo"

    username = Column(VARCHAR, nullable=False, primary_key=True)
    hashed_password = Column(VARCHAR, nullable=False)
    userType = Column(VARCHAR, nullable=False)
    disabled = Column(Boolean, nullable=False)