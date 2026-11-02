
from pydantic import BaseModel, Field, field_validator


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters")

    if not any(character.isupper() for character in password):
        raise ValueError("Password must contain at least one uppercase letter")

    if not any(character.islower() for character in password):
        raise ValueError("Password must contain at least one lowercase letter")

    if not any(character.isdigit() for character in password):
        raise ValueError("Password must contain at least one number")

    return password


class EmailData(BaseModel):
    email: str = Field(
        min_length=5,
        max_length=254,
        pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$",
    )


class UserCredentials(EmailData):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return validate_password_strength(password)


class OtpVerificationData(EmailData):
    otp: str = Field(pattern=r"^\d{6}$")


class PasswordResetData(EmailData):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, password: str) -> str:
        return validate_password_strength(password)
