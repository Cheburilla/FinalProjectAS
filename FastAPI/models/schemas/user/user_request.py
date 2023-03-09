from pydantic import BaseModel


class UserRequest(BaseModel):
    username: str
    password_text: str
    role: str
