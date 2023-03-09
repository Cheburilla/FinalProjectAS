from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException
from jose import JWTError
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from models.schemas.utils.jwt_token import JwtToken
from src.core.settings import settings
from src.models.base import Base


class User(Base):
    __tablename__ = 'Users'
    __table_args__ = {'extend_existing': True}
    id = Column(Integer, primary_key=True)
    username = Column(String)
    password_hash = Column(String)
    role = Column(String)
    created_at = Column(DateTime)
    created_by = Column(Integer, ForeignKey(
        'Users.id'), index=True, nullable=True)
    modified_at = Column(DateTime, nullable=True)
    modified_by = Column(Integer, ForeignKey(
        'Users.id'), index=True, nullable=True)
