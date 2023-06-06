
# run web page ->  uvicorn main:app --reload        ## main->file name  // app->app name


from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Annotated, Union
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta, datetime
from pydantic import BaseModel
from collections import OrderedDict
import os
import json
#database
from database import engineconn
from models import DBtable


#--- JWT setting ---#
# to get a string like this run:
# openssl rand -hex 32

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(BASE_DIR, "secrets.json")
secrets = json.loads(open(SECRET_FILE).read())

SECRET_KEY = secrets["server"]["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    userType: str
    username: str
    disabled: bool


class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()



# templets = Jinja2Templates(directory="templates")

# app.mount("/static", StaticFiles(directory="static"), name="static")




origins = [
    "http://localhost:3000",
    "localhost:3000"
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*","Authorization"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str): #use mysql
    try:
        information = session.query(db).get(username)
    except:
        print(f"[{datetime.utcnow()}] DATABASE DOWN")
        return 
    if information != None: # Is it ok?
        user_dict = {
            "userType":information.userType,
            "username":information.username,
            "hashed_password":information.hashed_password,
            "disabled" : information.disabled
            }
        return UserInDB(**user_dict)
        #return UserInDB(user_dict)
    else:
        return
    
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        print(f"[{datetime.utcnow()}] \"{username}\" is not exist in database.")
        return False
    if not verify_password(password, user.hashed_password):
        print(f"[{datetime.utcnow()}] \"{username}\" password not correct.")
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(DBtable, username=token_data.username)#changed
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



#------#





#---database---#

"""
mysql
homeHomepageDB
table : userInfo


mysql -u root -p

mysql.server start
mysql.server stop
"""

#DBtable is database.

engine = engineconn()
session = engine.sessionmaker()

class Item(BaseModel):
    username: str
    hashed_password: str
    userType: str
    disabled: bool





# user:2345
#------#

#token
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = authenticate_user(DBtable, form_data.username, form_data.password)
    if not user:
        raise HTTPException(#raise login failed alert
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    print(f"[{datetime.utcnow()}] \"{form_data.username}\" get access token")
    #print(form_data.username, form_data.password) #for test
    #print(f"[{datetime.utcnow()}]\n",{"access_token": access_token, "token_type": "bearer"}) #for test

    return {"access_token": access_token, "token_type": "bearer"}



@app.post("/userinfo", response_model=User)
async def read_users_me(
    current_user: User = Depends(get_current_active_user)
):
    return current_user


#mysql test
# @app.get("/")
# async def first_get():
#     example = session.query(DBtable).get("admin")
#     return example