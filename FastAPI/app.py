from fastapi import FastAPI
from src.api.base_router import router

tags_dict = [
    {
        'name': 'authorization',
        'description': 'Авторизация и регистрация пользователей'
    }
]


def admin_check() -> None:
    with Session.begin() as session:
        user = (
            session
            .query(User)
            .filter(User.role == 'admin')
            .first()
        )
        if not user:
            admin = User(
                id=1,
                username=settings.admin_username,
                password_hash=UserService.hash_password(
                    settings.admin_password),
                role='admin'
            )
            session.add(admin)
            session.commit()


app = FastAPI(
    title='Мое второе приложение FastAPI',
    description='Приложение для работы с резервуарами',
    version='alpha',
    openapi_tags=tags_dict,
    on_startup=[admin_check]
)

app.include_router(router)
