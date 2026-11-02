
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, Session

from db_base import Base
from models import User

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing from .env")

engine = create_engine(
    DATABASE_URL,
    echo=True
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_email(db: Session, email: str):
    statement = select(User).where(User.email == email)
    return db.scalar(statement)


def create_user(db: Session, email: str, password_hash: str):
    user = User(
        email=email,
        password_hash=password_hash
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def update_user_password(db: Session, email: str, password_hash: str):
    user = get_user_by_email(db, email)

    if not user:
        return False

    user.password_hash = password_hash
    db.commit()

    return True
