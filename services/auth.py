import jwt
from config import config
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Request
from jwt import PyJWTError
from pydantic import BaseModel, EmailStr
from pydash import _
from starlette.responses import JSONResponse


# Mock user repository
user_repository = [
    {"id": 1, "email": "james@james.james", "password": "1234567"},
    {"id": 2, "email": "james1@james.james", "password": "1234567"},
    {"id": 3, "email": "james2@james.james", "password": "1234567"},
    {"id": 4, "email": "james3@james.james", "password": "1234567"},
]

# This should be saved to memory, for now we will use it as cache
refresh_token_blacklist_cache = [
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJyZWZyZXNoX3Rva2VuIjp0cnVlLCJleHAiOjE1OTIwNzY0NTJ9.dOLKiT-872-OlzbEhOUAEig3jpaswSd_VT1FrbJh0k4"
]

class Token(BaseModel):
    access_token: str
    token_type: str

class AuthResponse(BaseModel):
    bearer: Token
    refresh: Token

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

def __create_refresh_token(data: dict):
    data_to_encode = data.copy()
    # Set the type of token to refresh
    data_to_encode["refresh_token"] = True
    expire = datetime.utcnow() + timedelta(minutes=config.env.refresh_token_expire_minutes)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(data_to_encode, config.env.token_secret_key, algorithm=config.env.token_algorithm)
    return encoded_jwt

def __create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=config.env.token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config.env.token_secret_key, algorithm=config.env.token_algorithm)
    return encoded_jwt

# Middleware to validate auth
async def auth_middleware(request: Request, call_next):
    try:
        if request.url.path == "/auth" and request.method == "POST":
            response = await call_next(request)
            return response

        authorization_header: str = request.headers["Authorization"]
        token: str = _.replace(authorization_header, "Bearer ", "", ignore_case=True)
        payload = jwt.decode(token, config.env.token_secret_key, algorithm=config.env.token_algorithm)
        user_id = payload.get("user_id")
        if user_id is None:
            return JSONResponse({"detail": "user_id is None: Could not validate credentials"})

        request.state.user_id = user_id
        response = await call_next(request)
        return response
    except PyJWTError:
        return JSONResponse({"detail": "PyJWTError: Could not validate credentials"}, status_code=500)

router = APIRouter()

@router.post("/auth", tags=["authentication"], response_model=AuthResponse)
async def login_user(credentials: LoginRequest):
    email: str = credentials.email
    password: str = credentials.password

    user = _.find(user_repository, {"email": email, "password": password })
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid credentials or user not found")

    # Note that you can pass any data to encode, for example the user IP if you want tokens to be assigned to a single IP
    jwt_token = __create_access_token({"user_id": user["id"]})
    refresh_token = __create_refresh_token({"user_id": user["id"]})

    return {
        "bearer": {
            "access_token": jwt_token,
            "token_type": "bearer"
        },
        "refresh": {
            "access_token": refresh_token,
            "token_type": "refresh"
        }
    }


@router.post("/auth/refresh", tags=["authentication"], response_model=AuthResponse)
async def refresh_auth(payload: Token, request: Request):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # TODO: get access_token from middleware, check that user ids match so you can refresh
        isTokenInCache = _.find(refresh_token_blacklist_cache, lambda token: token == payload.access_token)
        if(isTokenInCache):
            raise credentials_exception

        decoded_token = jwt.decode(payload.access_token, config.env.token_secret_key, algorithm=config.env.token_algorithm)
        user_id = decoded_token.get("user_id")
        if user_id is None or user_id != request.state.user_id:
            raise credentials_exception

        is_refresh_token = decoded_token.get("refresh_token")
        if is_refresh_token != True:
            raise HTTPException(400, "Invalid token type")

        jwt_token = __create_access_token({"user_id": user_id})

        return {
            "bearer": {
                "access_token": jwt_token,
                "token_type": "bearer"
            },
            "refresh": {
                "access_token": payload.access_token,
                "token_type": "refresh"
            }
        }
    except PyJWTError:
        raise credentials_exception


@router.delete("/auth", tags=["authentication"])
async def read_user(payload: Token, request: Request):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        decoded_token = jwt.decode(payload.access_token, config.env.token_secret_key, algorithm=config.env.token_algorithm)
        is_refresh_token = decoded_token.get("refresh_token")
        if is_refresh_token != True:
            raise HTTPException(400, "Invalid token type")

        user_id = decoded_token.get("user_id")
        if user_id is None or user_id != request.state.user_id:
            # If a refresh token does not match the user token then one of the tokens might have been stolen
            # We should definitely blacklist the refresh token
            refresh_token_blacklist_cache.append(payload.access_token)
            raise HTTPException(401, "Invalid refresh token for user, one of these tokens might have been stolen")

        refresh_token_blacklist_cache.append(payload.access_token)

        return {"status": 200}
    except PyJWTError:
        raise credentials_exception