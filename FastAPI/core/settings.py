from pydantic import BaseSettings


class Settings(BaseSettings):
    host: str = 'localhost'
    port: int = 9999
    connection_string: str
    jwt_secret: str
    jwt_algorithm: str
    jwt_expires_seconds: int
    admin_username: str
    admin_password: str


settings = Settings(
    _env_file='..\.env',
    _env_file_encoding='utf-8',
)
