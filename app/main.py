from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, WebSocket, WebSocketDisconnect, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.models import User, SessionLocal, init_db, Base
from typing import List, Dict
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import timedelta
import app.security as security
import asyncio


active_sessions: Dict[str, Dict[str, WebSocket]] = {}

templates = Jinja2Templates(directory="app/templates")

tags = [
    {
        "name": "users",
        "description": "Управление пользователями",
    },

    {
        "name": "sessions",
        "description": "Активные сессии",
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

class DataTable(BaseModel):
    strong_index: List[int]
    css: List[str]


class UserCreate(BaseModel):
    realname: str
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


@app.post("/signup", summary="Registration", tags=["users"])
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    em = db.query(User).filter(User.email == user_data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="there is already such a user! try another username ( ͡° ͜ʖ ͡°)")
    if em:
        raise HTTPException(status_code=400, detail="there is already such an email! try another email ( ͡° ͜ʖ ͡°)")

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


@app.delete("/del", tags=["users"])
async def delete_account(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=418, detail="we don't have any here! try registration or check /docs")

    if not security.verify_pass(password, user.hashed_password):
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


async def authenticate_websocket(websocket: WebSocket, db: Session):
    token = websocket.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise HTTPException(status_code=401, detail="missing or invalid token")

    token_data = token.split("Bearer ")[1]
    username = security.verify_token(token_data)

    user = db.query(User).filter(User.username == username).first()
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise HTTPException(status_code=401, detail="invalid token")

    return username



@app.websocket("/ws/{username}")
async def user_session(username: str, websocket: WebSocket, db: Session = Depends(get_db)):
    user_from_token = await authenticate_websocket(websocket, db)

    if username != user_from_token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise HTTPException(status_code=403, detail="token username mismatch")

    if username in active_sessions:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise HTTPException(status_code=403, detail="user already has an active session")

    await websocket.accept()
    active_sessions[username] = {"user": websocket, "doctor": None}

    try:
        while True:
            data = await websocket.receive_json()
            if active_sessions[username]["doctor"]:
                await active_sessions[username]["doctor"].send_json(data)
    except WebSocketDisconnect:
        del active_sessions[username]


@app.websocket("/ws/doctor/{username}")
async def doctor_session(username: str, websocket: WebSocket):
    if username not in active_sessions:
        await websocket.close()
        raise HTTPException(status_code=404, detail="no active session for this user")

    await websocket.accept()
    active_sessions[username]["doctor"] = websocket

    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        active_sessions[username]["doctor"] = None


@app.get("/activea", tags=["sessions"])
async def active_ws():
    return {"active_sessions": list(active_sessions.keys())}