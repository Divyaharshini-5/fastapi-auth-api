from datetime import datetime

# Temporary in-memory OTP storage. Reset requests are lost when the app restarts.
password_resets: dict[str, dict[str, str | datetime]] = {}
