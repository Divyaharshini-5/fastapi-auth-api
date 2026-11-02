
from fastapi import FastAPI

from routes.auth import router as auth_router


app = FastAPI(
    title="FastAPI Authentication API",
    version="1.0.0",
)

app.include_router(auth_router)
