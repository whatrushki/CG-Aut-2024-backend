from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.models import User, SessionLocal, init_db
from typing import List, Dict
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import timedelta
import app.security as security
import asyncio


templates = Jinja2Templates(directory="app/templates")

tags = [
    {
        "name": "users",
        "description": "Управление пользователями",
    },
]

app = FastAPI(
    title="WHAT | Hackathon API",
    description="Backend for Cybergarden Hackathon 2024",
    version="1.0.1",
    openapi_tags=tags,
    redoc_url=None,
    docs_url="/papers",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Token(BaseModel):
    access_token: str
    token_type: str
    realname: str


class UserCreate(BaseModel):
    realname: str
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str


@app.post("/signup", summary="now JSON !!!", tags=["users"])
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    em = db.query(User).filter(User.email == user_data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="there is already such a user! try another username ( ͡° ͜ʖ ͡°)")
    if em:
        raise HTTPException(status_code=400, detail="there is already such a email! try another email ( ͡° ͜ʖ ͡°)")

    hashed_password = security.hash_pass(user_data.password)

    new_user = User(username=user_data.username, email=user_data.email, hashed_password=hashed_password, realname=user_data.realname)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"status_code": 200, "message": ".·´¯`·.´¯`·.¸¸.·´¯`·.¸><(((º> "}


@app.post("/login", response_model=Token, tags=["users"])
async def login(login_data: UserLogin, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.username == login_data.username).first()

    if not user or not security.verify_pass(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="password or login is wrong!",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "realname": user.realname
    }

@app.get("/profile", deprecated=True, tags=["users"])
async def profile(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=403, detail="we don't have any here! try registration or check /docs")
    return {"username": user.username, "email": user.email}


@app.get("/profile/{username}", tags=["users"])
async def profile(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=403, detail="we don't have any here! try registration or check /docs")
    return {"username": user.username, "email": user.email}


@app.delete("/del", tags=["users"])
async def delete_account(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=418, detail="we don't have any here! try registration or check /docs")

    if not security.verify_password(password, user.hashed_password):
        raise HTTPException(status_code=403, detail="password is wrong!")
    db.delete(user)
    db.commit()
    return {"status_code": 200, "detail": "User deleted success (✖╭╮✖)"}

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def redir():
    return RedirectResponse("/home")
@app.get("/home", response_class=HTMLResponse, include_in_schema=False)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.exception_handler(StarletteHTTPException)
async def code404(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return JSONResponse(
            status_code=404,
            content={"message": "page not found, check docs!"}
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )



# Печеньки
# @app.get("/t")
# def root(response: Response):
#     now = datetime.now()
#     response.set_cookie(key="last_visit", value=now)
#     return  {"message": "cookie setted"}


#
# данные пользователя выгружаются на бекенд через websocket
# в любой момент к комнате пользователя может подключиться медбрат и просматреть данные пользователя


#РЕГА
# реальное имя
# отображаемое имя
# почта
# пароль

# иметь аккаунт пользователя
# сохранять анализы в базе данных