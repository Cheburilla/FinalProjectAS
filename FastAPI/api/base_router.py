from fastapi import APIRouter

from src.api import operation, product, tank, user

router = APIRouter()
router.include_router(operation.router)
router.include_router(product.router)
router.include_router(tank.router)
router.include_router(user.router)
