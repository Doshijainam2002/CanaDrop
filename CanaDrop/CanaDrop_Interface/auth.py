import jwt
from django.conf import settings
from django.http import JsonResponse
from functools import wraps
from .models import *

def pharmacy_auth_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get("authToken")

        if not token:
            return JsonResponse(
                {"success": False, "error": "Not authenticated"},
                status=401
            )

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            return JsonResponse(
                {"success": False, "error": "Session expired"},
                status=401
            )
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"success": False, "error": "Invalid token"},
                status=401
            )

        try:
            pharmacy = Pharmacy.objects.get(id=payload["pharmacy_id"])
        except Pharmacy.DoesNotExist:
            return JsonResponse(
                {"success": False, "error": "Invalid user"},
                status=401
            )

        # 🔥 Attach authenticated user to request
        request.pharmacy = pharmacy

        return view_func(request, *args, **kwargs)

    return wrapper


def driver_auth_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get("authToken")

        if not token:
            return JsonResponse(
                {"success": False, "error": "Not authenticated"},
                status=401
            )

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            return JsonResponse(
                {"success": False, "error": "Session expired"},
                status=401
            )
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"success": False, "error": "Invalid token"},
                status=401
            )

        driver_id = payload.get("driver_id")
        if not driver_id:
            return JsonResponse(
                {"success": False, "error": "Invalid token payload"},
                status=401
            )

        try:
            driver = Driver.objects.get(id=driver_id, active=True)
        except Driver.DoesNotExist:
            return JsonResponse(
                {"success": False, "error": "Invalid user"},
                status=401
            )

        # 🔥 Attach authenticated driver to request
        request.driver = driver

        return view_func(request, *args, **kwargs)

    return wrapper


def user_auth_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get("authToken")
        if not token:
            return JsonResponse({"success": False, "error": "Not authenticated"}, status=401)

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            return JsonResponse({"success": False, "error": "Session expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"success": False, "error": "Invalid token"}, status=401)

        # Pharmacy user
        if "pharmacy_id" in payload:
            try:
                request.user_type = "pharmacy"
                request.user = Pharmacy.objects.get(id=payload["pharmacy_id"])
            except Pharmacy.DoesNotExist:
                return JsonResponse({"success": False, "error": "Invalid user"}, status=401)

        # Driver user
        elif "driver_id" in payload:
            try:
                request.user_type = "driver"
                request.user = Driver.objects.get(id=payload["driver_id"], active=True)
            except Driver.DoesNotExist:
                return JsonResponse({"success": False, "error": "Invalid user"}, status=401)

        else:
            return JsonResponse({"success": False, "error": "Invalid token payload"}, status=401)

        return view_func(request, *args, **kwargs)

    return wrapper


def admin_auth_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get("authToken")

        if not token:
            return JsonResponse(
                {"success": False, "error": "Not authenticated"},
                status=401
            )

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            return JsonResponse(
                {"success": False, "error": "Session expired"},
                status=401
            )
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"success": False, "error": "Invalid token"},
                status=401
            )

        admin_id = payload.get("admin_id")
        if not admin_id:
            return JsonResponse(
                {"success": False, "error": "Invalid token payload"},
                status=401
            )

        try:
            admin = AdminUser.objects.get(id=admin_id)
        except AdminUser.DoesNotExist:
            return JsonResponse(
                {"success": False, "error": "Invalid admin user"},
                status=401
            )

        # 🔥 Attach authenticated admin to request
        request.admin = admin
        request.user_type = "admin"

        return view_func(request, *args, **kwargs)

    return wrapper