import jwt
from django.conf import settings
from django.http import JsonResponse
from functools import wraps
from .models import Pharmacy

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
