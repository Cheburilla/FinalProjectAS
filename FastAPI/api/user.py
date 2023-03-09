from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from models.schemas.user.user_request import UserRequest
from models.schemas.user.user_response import UserResponse
from models.schemas.utils.jwt_token import JwtToken
from services.user import (UserService, get_current_user_id,
                           get_current_user_rights)
from src.api.utils.get_with_check import get_with_check

router = APIRouter(
    prefix='/users',
    tags=['users']
)


@router.get('/all', response_model=List[UserResponse], name='Получить всех пользователей')
def get(user_service: UserService = Depends(), admin_id: int = Depends(get_current_user_rights)):
    print(admin_id)
    return user_service.all()


@router.get('/get/{user_id}', response_model=UserResponse, name='Получить одного пользователя')
def get(user_id: int, user_service: UserService = Depends(), admin_id: int = Depends(get_current_user_rights)):
    print(admin_id)
    return get_with_check(user_id, user_service)


@router.post('/', response_model=UserResponse, status_code=status.HTTP_201_CREATED, name='Добавить пользователя')
def add(user_schema: UserRequest, user_service: UserService = Depends(), creating_id: int = Depends(get_current_user_rights)):
    return user_service.add(user_schema, creating_id)


@router.put('/{user_id}', response_model=UserResponse, name='Обновить информацию о пользователе')
def put(user_id: int, user_schema: UserRequest, user_service: UserService = Depends(), modifying_id: int = Depends(get_current_user_rights)):
    get_with_check(user_id, user_service)
    return user_service.add(user_schema, modifying_id)


@router.delete('/{user_id}', status_code=status.HTTP_204_NO_CONTENT, name='Удалить пользователя')
def delete(user_id: int, user_service: UserService = Depends(), admin_id: int = Depends(get_current_user_rights)):
    print(admin_id)
    get_with_check(user_id, user_service)
    return user_service.delete(user_id)


@router.post('/register', status_code=status.HTTP_201_CREATED, name='Регистрация пользователя')
def register(user_schema: UserRequest, users_service: UserService = Depends(), admin_id: int = Depends(get_current_user_rights)):
    print(admin_id)
    return users_service.register(user_schema)


@router.post('/authorize', response_model=JwtToken, name='Авторизация пользователя')
def authorize(auth_schema: OAuth2PasswordRequestForm = Depends(), users_service: UserService = Depends()):
    result = users_service.authorize(
        auth_schema.username, auth_schema.password)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Пользователь не авторизован')
    return result
