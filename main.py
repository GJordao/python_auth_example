from fastapi import FastAPI
from config import config
from services import auth
from services.auth import auth_middleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()
app.include_router(auth.router)
app.add_middleware(BaseHTTPMiddleware, dispatch=auth_middleware)

@app.get("/")
def read_root():
    return {"Healthcheck": "ok"}