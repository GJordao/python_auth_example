from pydantic import BaseSettings

class Env(BaseSettings):
    mode: str = "prod"
    token_secret_key: str
    token_algorithm: str = "HS256"
    token_expire_minutes: int = 60
    refresh_token_expire_minutes: int = 43200


env = Env()