
# run web page ->  uvicorn main:app --reload        ## main->file name  // app->app name

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Response, Header
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
from pathlib import Path
import os
import json
import cv2
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
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 1



class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


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
    "localhost:3000",
    "http://raspinas.iptime.org:3000",
    "raspinas.iptime.org:3000"
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
    except Exception as e:
        print(e)
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

def create_refresh_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=1)
    to_encode.update({"refresh":"token", "exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_refresh_token(token: str ):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        #headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("refresh") != "token":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        exp: str = payload.get("exp")
        if exp is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(DBtable, username=username)
    if user is None:
        raise credentials_exception
    return user


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
    except JWTError:
        raise credentials_exception
    user = get_user(DBtable, username=username)
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

port=9000


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
async def response_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    session.close()
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
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    print(f"[{datetime.utcnow()}] \"{form_data.username}\" get access token")
    #print(form_data.username, form_data.password) #for test
    #print(f"[{datetime.utcnow()}]\n",{"access_token": access_token, "token_type": "bearer"}) #for test
    session.close()
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@app.post("/refreshToken", response_model=Token)
async def response_refresh_token(refresh_token: str=Form(...)):
    session.close()
    user = authenticate_refresh_token(refresh_token)
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
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    print(f"[{datetime.utcnow()}] \"{user.username}\" get access token")
    session.close()
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

    



@app.post("/userinfo", response_model=User)
async def read_users_me(
    current_user: User = Depends(get_current_active_user)
):
    session.close()
    return current_user #give : username,usertype,disabled


@app.post("/changepassword")
async def changepassword(username: str = Form(...), currentPassword: str = Form(...), newPassword: str = Form(...)):
    session.close()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        #headers={"WWW-Authenticate": "Bearer"},
    )
    if authenticate_user(DBtable, username, currentPassword):
        session.query(DBtable).filter_by(username = username).update({"hashed_password": get_password_hash(newPassword)})
        session.commit()
        session.close()
    else:
        raise credentials_exception
    return

@app.post("/getmusiclist")
async def getmusiclist(current_user: User = Depends(get_current_active_user)):
    pathDir = "./assets/music/"+current_user.username
    fileList = os.listdir(pathDir)
    fileList.sort()
    list = []
    for i in range(len(fileList)):
        list.append({"id":i, "data":fileList[i]})

    return {"len":len(fileList),"data":list}

@app.post("/getmusicfile")
async def getmusicfile(current_user: User = Depends(get_current_active_user), musicName: str = Form(...)):


    pathDir = "./assets/music/"+current_user.username+"/"+musicName
    print(pathDir)
    if os.path.isfile(pathDir):
        print('File exist')
    else:
        raise HTTPException(#raise login failed alert
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File dose not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return

@app.post("/getvideolist")
async def getvideolist(current_user: User = Depends(get_current_active_user)):
    pathDir = "./assets/video/"+current_user.username
    fileList = os.listdir(pathDir)
    fileList.sort()
    list = []
    for i in range(len(fileList)):
        list.append({"id":i, "data":fileList[i]})
    
    return {"len":len(fileList),"data":list}


@app.get("/getvideofile/{item_id}")
async def getvideofile(item_id: str, token: str, range: str = Header(None)):

    print("video file called")

#if changed to yeild, use it. 
    # temp = int(range.replace("bytes=", "").replace("-",""))
    # range += str(temp + 1000)


    print(range)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        #headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise credentials_exception



    pathDir = "./assets/video/"+payload['sub']+"/"+item_id


    cv2Video = cv2.VideoCapture(pathDir)
    width = int(cv2Video.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cv2Video.get(cv2.CAP_PROP_FRAME_HEIGHT))
    CHUNK_SIZE = width*height
    video_path = Path(pathDir)
    start, end = range.replace("bytes=", "").split("-")
    start = int(start)
    end = int(end) if end else start + CHUNK_SIZE

#change to yeild

    with open(video_path, "rb") as video:
        video.seek(start)
        data = video.read(end - start)
        filesize = str(video_path.stat().st_size)
        headers = {
            'Content-Range': f'bytes {str(start)}-{str(end)}/{filesize}',
            'Accept-Ranges': 'bytes'
        }
        return Response(data, status_code=206, headers=headers, media_type="video/mp4")


