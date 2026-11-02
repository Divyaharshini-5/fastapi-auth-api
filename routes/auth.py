
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import (
    create_user,
    get_db,
    get_user_by_email,
    update_user_password,
)
from schemas.auth import (
    EmailData,
    OtpVerificationData,
    PasswordResetData,
    UserCredentials,
)
from services.email_service import EmailServiceError, send_password_reset_otp
from services.passwords import hash_password, verify_password
from storage.password_resets import password_resets


router = APIRouter(tags=["authentication"])


@router.post("/register")
def register(
    data: UserCredentials,
    db: Session = Depends(get_db),
):
    if get_user_by_email(db, data.email):
        raise HTTPException(
            status_code=400,
            detail="Email already exists",
        )

    try:
        create_user(
            db,
            data.email,
            hash_password(data.password),
        )
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Email already exists",
        ) from error

    return {
        "message": "User registered successfully",
        "email": data.email,
    }


@router.post("/login")
def login(
    data: UserCredentials,
    db: Session = Depends(get_db),
):
    user = get_user_by_email(db, data.email)

    if not user or not verify_password(
        data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    return {
        "message": "Login successful",
        "email": data.email,
    }


@router.post("/forgot-password")
def forgot_password(
    data: EmailData,
    db: Session = Depends(get_db),
):
    if get_user_by_email(db, data.email):
        otp = f"{secrets.randbelow(1_000_000):06d}"

        password_resets[data.email] = {
            "otp_hash": hashlib.sha256(otp.encode()).hexdigest(),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        }

        try:
            send_password_reset_otp(data.email, otp)
        except EmailServiceError as error:
            password_resets.pop(data.email, None)
            raise HTTPException(
                status_code=503,
                detail=str(error),
            ) from error

    return {
        "message": "If that email is registered, a 6-digit OTP has been sent."
    }


@router.post("/verify-reset-otp")
def verify_reset_otp(data: OtpVerificationData):
    reset = password_resets.get(data.email)

    if not reset or reset["expires_at"] < datetime.now(timezone.utc):
        password_resets.pop(data.email, None)
        raise HTTPException(
            status_code=400,
            detail="OTP is invalid or has expired",
        )

    otp_hash = hashlib.sha256(data.otp.encode()).hexdigest()

    if not hmac.compare_digest(otp_hash, reset["otp_hash"]):
        raise HTTPException(
            status_code=400,
            detail="OTP is invalid or has expired",
        )

    reset["verified"] = "true"

    return {
        "message": "OTP verified. Choose a new password."
    }


@router.post("/reset-password")
def reset_password(
    data: PasswordResetData,
    db: Session = Depends(get_db),
):
    reset = password_resets.get(data.email)

    if (
        not reset
        or reset["expires_at"] < datetime.now(timezone.utc)
        or reset.get("verified") != "true"
    ):
        password_resets.pop(data.email, None)
        raise HTTPException(
            status_code=400,
            detail="Verify your OTP before changing the password",
        )

    if update_user_password(
        db,
        data.email,
        hash_password(data.new_password),
    ):
        password_resets.pop(data.email, None)

        return {
            "message": "Password changed successfully. You can now log in."
        }

    raise HTTPException(
        status_code=400,
        detail="OTP is invalid or has expired",
    )
