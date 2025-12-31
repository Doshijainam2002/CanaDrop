from pathlib import Path
import os
import tempfile
from ..aws_secrets import get_secret
import pytz

# ----------------------------
# BASE DIRECTORY
# ----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ----------------------------
# LOAD SECRETS
# ----------------------------
secrets = get_secret("canadrop/app-keys")

# ----------------------------
# SECURITY
# ----------------------------
SECRET_KEY = secrets.get("DJANGO_SECRET_KEY")
DEBUG = False
# ALLOWED_HOSTS = ["*"]
ALLOWED_HOSTS = [
    "www.canalogistix.com",
    "canalogistix.com",
    "3.143.255.134",
]

if DEBUG:
    raise RuntimeError("DEBUG must never be True in production")


# ----------------------------
# APPLICATION DEFINITION
# ----------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'CanaDrop_Interface',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'CanaDrop.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'CanaDrop.wsgi.application'

# ----------------------------
# DATABASE CONFIGURATION
# ----------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'canadrop',
        'USER': 'canauser',
        'PASSWORD': secrets.get("RDS_PASSWORD"),
        'HOST': 'canadrop-db.clyay8k067j8.us-east-2.rds.amazonaws.com',
        'PORT': '5432',
    }
}

# ----------------------------
# PASSWORD VALIDATION
# ----------------------------
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

# ----------------------------
# INTERNATIONALIZATION
# ----------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

USER_TIMEZONE = pytz.timezone("America/Toronto")

# ----------------------------
# STATIC FILES
# ----------------------------
STATIC_URL = 'static/'

# ----------------------------
# DEFAULT AUTO FIELD
# ----------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ----------------------------
# EXTERNAL KEYS / SERVICES
# ----------------------------
GOOGLE_MAPS_API_KEY = secrets.get("GOOGLE_MAPS_API_KEY")
STRIPE_PUBLISHABLE_KEY = secrets.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_SECRET_KEY = secrets.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = secrets.get("STRIPE_WEBHOOK_SECRET")   

# ----------------------------
# GCP SERVICE ACCOUNT TEMP FILE
# ----------------------------
gcp_key_json = secrets.get("gcp_service_account")
with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
    f.write(gcp_key_json.encode())
    GCP_KEY_PATH = f.name

# ----------------------------
# DJANGO EMAIL SERVICE SETUP
# ----------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_TIMEOUT = 30 

EMAIL_HELP_DESK = "help.canalogistix@gmail.com"
EMAIL_ADMIN_OFFICE = "office.canalogistix@gmail.com"
EMAIL_OPERATIONS = "operations.canalogistix@gmail.com"
EMAIL_BILLING = "billing.canalogistix@gmail.com"  

EMAIL_CREDENTIALS = {
    EMAIL_HELP_DESK: secrets.get("GMAIL_APP_PASSWORD_HELP_DESK"),
    EMAIL_ADMIN_OFFICE: secrets.get("GMAIL_APP_PASSWORD_ADMIN_MANAGEMENT"),
    EMAIL_OPERATIONS: secrets.get("GMAIL_APP_PASSWORD_OPERATIONS"),
    EMAIL_BILLING: secrets.get("GMAIL_APP_PASSWORD_BILLING_AND_INVOICING"),
}

DEFAULT_FROM_EMAIL = EMAIL_HELP_DESK

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "django_cache",   # table name
        "TIMEOUT": 3600,              # per-key TTLs still apply (e.g., OTP_TTL_SECONDS)
    }
}


OTP_TTL_SECONDS = 10 * 60
VERIFY_TOKEN_TTL_SECONDS = 15 * 60
OTP_SIGNING_SALT = "canadrop-otp-verify"

GCP_BUCKET_NAME = "canadrop-bucket"
GCP_INVOICE_FOLDER = "PharmacyInvoices"
GCP_CUSTOMER_PHARMACY_SIGNED_ACKNOWLEDGEMENTS = "PharmacySignedAcknowledgements"
GCP_DRIVER_INVOICE_FOLDER = "DriverSummary"
GCP_DRIVER_PROFILE_FOLDER = "DriverProfileImages"
GCP_PROOF_FOLDER = "Proof"

LOGO_PATH = os.path.join(BASE_DIR, "Logo", "Website_Logo_No_Background.png")
LOGO_URL = "https://canalogistix.s3.us-east-2.amazonaws.com/Logo/CanaLogistiX_Logo_BG.png"

# ----------------------------
# BUSINESS INFORMATION
# ----------------------------
COMPANY_OPERATING_NAME = secrets.get("COMPANY_OPERATING_NAME")
COMPANY_SUB_GROUP_NAME = secrets.get("COMPANY_SUB_GROUP_NAME")
CORPORATION_NAME = secrets.get("CORPORATION_NAME")
COMPANY_BUSINESS_NUMBER = secrets.get("COMPANY_BUSINESS_NUMBER")

BRAND_COLORS = {
    'primary': '#0d9488',
    'primary_dark': '#0f766e',
    'accent': '#06b6d4',
    'bg_dark': '#0b1220',
    'card_dark': '#0f172a',
    'border_dark': '#1f2937',
    'text_light': '#e5e7eb',
    'text_muted': '#94a3b8',
}


DRIVER_COMMISSION_RATE = 0.40
PAYMENT_RATE_PERCENT = int(100 - (100 * DRIVER_COMMISSION_RATE))

SITE_URL = "https://www.canalogistix.com"

CC_POINTS_PER_ORDER = 50

ONTARIO_HST_RATE = "0.13"
ONTARIO_HST_PERCENT = "13"

# ----------------------------
# JWT SETTINGS (Centralized)
# ----------------------------
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
JWT_SECRET_KEY = secrets.get("JWT_SECRET_KEY")


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'invoice_generation.log',
        },
        'route_file': {  # Add this new handler
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'route_optimization.log',
        },
    },
    'loggers': {
        'CanaDrop_Interface': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'CanaDrop_Interface.views': {  # Add this for route optimization
            'handlers': ['route_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
