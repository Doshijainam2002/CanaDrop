from pathlib import Path
import os
import pytz
from dotenv import load_dotenv

# -------------------------------------------------
# LOAD ENV
# -------------------------------------------------
load_dotenv()

# -------------------------------------------------
# BASE DIRECTORY
# -------------------------------------------------
# dev.py → settings → CanaDrop → project root
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# -------------------------------------------------
# SECURITY
# -------------------------------------------------
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Missing DJANGO_SECRET_KEY in .env")

# -------------------------------------------------
# APPLICATION DEFINITION
# -------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "CanaDrop_Interface",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "CanaDrop.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "CanaDrop.wsgi.application"

# -------------------------------------------------
# DATABASE (LOCAL POSTGRES)
# -------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
    }
}

if not DATABASES["default"]["NAME"]:
    raise RuntimeError("Missing DB_NAME in .env")

# -------------------------------------------------
# PASSWORD VALIDATION
# -------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# -------------------------------------------------
# INTERNATIONALIZATION
# -------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

USER_TIMEZONE = pytz.timezone("America/Toronto")

# -------------------------------------------------
# STATIC FILES
# -------------------------------------------------
STATIC_URL = "/static/"

# -------------------------------------------------
# DEFAULT AUTO FIELD
# -------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# -------------------------------------------------
# EXTERNAL KEYS / SERVICES (DEV)
# -------------------------------------------------
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")

STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# -------------------------------------------------
# GCP (LOCAL PATH)
# -------------------------------------------------
GCP_KEY_PATH = os.getenv("GCP_KEY_PATH", "")
GCP_BUCKET_NAME = os.getenv("GCP_BUCKET_NAME", "canadrop-bucket")
GCP_INVOICE_FOLDER = os.getenv("GCP_INVOICE_FOLDER", "PharmacyInvoices")
GCP_CUSTOMER_PHARMACY_SIGNED_ACKNOWLEDGEMENTS = os.getenv(
    "GCP_CUSTOMER_PHARMACY_SIGNED_ACKNOWLEDGEMENTS",
    "PharmacySignedAcknowledgements",
)
GCP_DRIVER_INVOICE_FOLDER = os.getenv("GCP_DRIVER_INVOICE_FOLDER", "DriverSummary")
GCP_DRIVER_PROFILE_FOLDER = os.getenv("GCP_DRIVER_PROFILE_FOLDER", "DriverProfileImages")
GCP_PROOF_FOLDER = os.getenv("GCP_PROOF_FOLDER", "Proof")

# -------------------------------------------------
# EMAIL (CONSOLE BY DEFAULT IN DEV)
# -------------------------------------------------
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend",
)

EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
EMAIL_TIMEOUT = int(os.getenv("EMAIL_TIMEOUT", 30))

EMAIL_HELP_DESK = os.getenv("EMAIL_HELP_DESK", "")
EMAIL_ADMIN_OFFICE = os.getenv("EMAIL_ADMIN_OFFICE", "")
EMAIL_OPERATIONS = os.getenv("EMAIL_OPERATIONS", "")
EMAIL_BILLING = os.getenv("EMAIL_BILLING", "")

EMAIL_CREDENTIALS = {
    EMAIL_HELP_DESK: os.getenv("GMAIL_APP_PASSWORD_HELP_DESK", ""),
    EMAIL_ADMIN_OFFICE: os.getenv("GMAIL_APP_PASSWORD_ADMIN_MANAGEMENT", ""),
    EMAIL_OPERATIONS: os.getenv("GMAIL_APP_PASSWORD_OPERATIONS", ""),
    EMAIL_BILLING: os.getenv("GMAIL_APP_PASSWORD_BILLING_AND_INVOICING", ""),
}

DEFAULT_FROM_EMAIL = EMAIL_HELP_DESK

# -------------------------------------------------
# CACHE
# -------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": os.getenv("CACHE_TABLE", "django_cache"),
        "TIMEOUT": int(os.getenv("CACHE_TIMEOUT_SECONDS", 3600)),
    }
}

# -------------------------------------------------
# OTP / SECURITY CONSTANTS
# -------------------------------------------------
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", 600))
VERIFY_TOKEN_TTL_SECONDS = int(os.getenv("VERIFY_TOKEN_TTL_SECONDS", 900))
OTP_SIGNING_SALT = os.getenv("OTP_SIGNING_SALT", "canadrop-otp-verify")

OTP_RATE_LIMIT_SECONDS = 60        # 1 OTP / minute
OTP_MAX_PER_HOUR = 5               # hard cap

# -------------------------------------------------
# APP CONSTANTS
# -------------------------------------------------
DRIVER_COMMISSION_RATE = float(os.getenv("DRIVER_COMMISSION_RATE", 0.40))
PAYMENT_RATE_PERCENT = int(100 - (100 * DRIVER_COMMISSION_RATE))

SITE_URL = os.getenv("SITE_URL", "http://localhost:8000")
CC_POINTS_PER_ORDER = int(os.getenv("CC_POINTS_PER_ORDER", 50))

# -------------------------------------------------
# JWT (MANDATORY)
# -------------------------------------------------
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", 24))

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("Missing JWT_SECRET_KEY in .env")


# -------------------------------------------------
# LOGO URL's
# -------------------------------------------------
LOGO_PATH = os.path.join(BASE_DIR, "Logo", "Website_Logo_No_Background.png")
LOGO_URL = "https://canalogistix.s3.us-east-2.amazonaws.com/Logo/CanaLogistiX_Logo_BG.png"

# -------------------------------------------------
# BUSINESS INFORMATION
# -------------------------------------------------
COMPANY_OPERATING_NAME = os.getenv("COMPANY_OPERATING_NAME")
COMPANY_SUB_GROUP_NAME = os.getenv("COMPANY_SUB_GROUP_NAME")
CORPORATION_NAME = os.getenv("CORPORATION_NAME")
COMPANY_BUSINESS_NUMBER = os.getenv("COMPANY_BUSINESS_NUMBER")

# -------------------------------------------------
# PROVINCIAL TAX INFORMATION
# -------------------------------------------------
ONTARIO_HST_RATE = "0.13"
ONTARIO_HST_PERCENT = "13"

# -------------------------------------------------
# LOGGING
# -------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
        },
    },

    "root": {
        "handlers": ["console"],
        "level": "DEBUG",
    },
}



BRAND_COLORS = {
    "primary": "#0d9488",
    "primary_dark": "#0f766e",
    "accent": "#06b6d4",
    "bg_dark": "#0b1220",
    "card_dark": "#0f172a",
    "border_dark": "#1f2937",
    "text_light": "#e5e7eb",
    "text_muted": "#94a3b8",
}
