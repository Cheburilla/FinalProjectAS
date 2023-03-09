from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.hash import pbkdf2_sha256

from core.settings import settings
from src.db.db import Session, get_session
from src.models.schemas.user.user_request import UserRequest
from src.models.schemas.utils.jwt_token import JwtToken
from src.models.user import User

oauth2_schema = OAuth2PasswordBearer(tokenUrl='/users/authorize')


def get_current_user_id(token: str = Depends(oauth2_schema)) -> int:
    return UserService.verify_token(token)


def get_current_user_rights(token: str = Depends(oauth2_schema)) -> int:
    return UserService.verify_access(token)


class UserService:
    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    @staticmethod
    def hash_password(password: str) -> str:
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def check_password(password_text: str, password_hash: str) -> bool:
        return pbkdf2_sha256.verify(password_text, password_hash)

    @staticmethod
    def create_token(user_id: int, role: str) -> JwtToken:
        now = datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + timedelta(seconds=settings.jwt_expires_seconds),
            'sub': str(user_id),
            'role': role
        }
        token = jwt.encode(payload, settings.jwt_secret,
                           algorithm=settings.jwt_algorithm)
        return JwtToken(access_token=token)

    @staticmethod
    def verify_token(token: str) -> Optional[int]:
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[
                                 settings.jwt_algorithm])
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Некорректный токен")
        return payload.get('sub')

    @staticmethod
    def verify_access(token: str) -> Optional[int]:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[
            settings.jwt_algorithm])
        if payload.get('role') != 'admin':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
        return payload.get('sub')

    def register(self, user_schema: UserRequest, creator_id: int) -> None:
        user = User(
            username=user_schema.username,
            password_hash=self.hash_password(user_schema.password_text),
            role=user_schema.role,
            created_at=datetime.now(),
            created_by=creator_id
        )
        self.session.add(user)
        self.session.commit()

    def authorize(self, username: str, password_text: str) -> Optional[JwtToken]:
        user = (
            self.session
            .query(User)
            .filter(User.username == username)
            .first()
        )

        if not user:
            return None
        if not self.check_password(password_text, user.password_hash):
            return None

        return self.create_token(user.id, user.role)

    def all(self) -> List[User]:
        users = (
            self.session
            .query(User)
            .order_by(
                User.id.desc()
            )
            .all()
        )
        return users

    def get(self, user_id: int) -> User:
        user = (
            self.session
            .query(User)
            .filter(
                User.id == user_id
            )
            .first()
        )
        return user

    def add(self, user_schema: UserRequest, creating_id: int) -> User:
        user = User(
            username=user_schema.username,
            password_hash=self.hash_password(user_schema.password_text),
            role=user_schema.role,
            created_by=creating_id,
            created_at=datetime.now()
        )
        self.session.add(user)
        self.session.commit()
        return user

    def update(self, user_id: int, user_schema: UserRequest, modifying_id: int) -> User:
        user = self.get(user_id)
        for field, value in user_schema:
            setattr(user, field, value)
        user.modified_at = datetime.now()
        user.modified_by = modifying_id
        self.session.commit()
        return user

    def delete(self, user_id: int):
        user = self.get(user_id)
        self.session.delete(user)
        self.session.commit()
