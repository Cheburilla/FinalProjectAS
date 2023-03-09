from datetime import datetime

from pydantic import BaseModel


class UserResponse(BaseModel):
    id: int
    username: str
    password_hash: str
    role: str
    created_at: datetime | None
    created_by: int | None
    modified_at: datetime | None
    modified_by: int | None

    class Config:
        orm_mode = True
