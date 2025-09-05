from pathlib import Path
import os
import tempfile
from .aws_secrets import get_secret

# ----------------------------
# BASE DIRECTORY
# ----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# ----------------------------
# LOAD SECRETS
# ----------------------------
secrets = get_secret("canadrop/app-keys")

# ----------------------------
# SECURITY
# ----------------------------
SECRET_KEY = secrets.get("DJANGO_SECRET_KEY")
DEBUG = False
ALLOWED_HOSTS = ["*"]

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
GMAIL_APP_PASSWORD = secrets.get("GMAIL_APP_PASSWORD")
GMAIL_ADDRESS = "help.canadrop@gmail.com"

# ----------------------------
# GCP SERVICE ACCOUNT TEMP FILE
# ----------------------------
gcp_key_json = secrets.get("gcp_service_account")
with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
    f.write(gcp_key_json.encode())
    GCP_KEY_PATH = f.name

# You can now use GCP_KEY_PATH in your code:
# Example:
# from google.cloud import storage
# client = storage.Client.from_service_account_json(settings.GCP_KEY_PATH)

# ----------------------------
# DJANGO EMAIL SERVICE SETUP
# ----------------------------

# settings.py
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = GMAIL_ADDRESS            # "help.canadrop@gmail.com"
EMAIL_HOST_PASSWORD = GMAIL_APP_PASSWORD   # 16-char app password
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "django_cache",   # table name
        "TIMEOUT": None,              # per-key TTLs still apply (e.g., OTP_TTL_SECONDS)
    }
}





LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'invoice_generation.log',
        },
    },
    'loggers': {
        'CanaDrop_Interface': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
