# Standard Library
import hashlib
import io
import json
import logging
import os
import random
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, time
from decimal import Decimal, InvalidOperation
from io import BytesIO
from itertools import chain
from random import sample
import mimetypes
import base64
import time
from .auth import *

# Third-Party Libraries
import googlemaps
import pytz
import requests
import stripe
from google.cloud import storage
from google.oauth2 import service_account
from ortools.constraint_solver import pywrapcp, routing_enums_pb2
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
)
from PIL import Image as PILImage
import jwt
import hmac
import re

# Django Core
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.mail import EmailMessage, EmailMultiAlternatives, get_connection
from django.core.signing import BadSignature, SignatureExpired, dumps, loads
from django.core.validators import validate_email
from django.db import IntegrityError, transaction, connection
from django.db.models import Count, Sum, Q, Exists, OuterRef
from django.http import (
    HttpRequest, HttpResponse, HttpResponseBadRequest,
    HttpResponseNotAllowed, JsonResponse
)
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.views.decorators.csrf import csrf_exempt, csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.utils.timezone import now
from django.template.loader import render_to_string

# Local App Models
from .models import *



# Add this for better error logging
logger = logging.getLogger(__name__)

# ----------------------------
# Helper Functions for Email
# ----------------------------
def _send_html_email_help_desk(subject: str, to_email: str, html: str, text_fallback: str = " "):
    from_email = settings.EMAIL_HELP_DESK
    connection = get_connection(
        username=from_email,
        password=settings.EMAIL_CREDENTIALS[from_email],
        fail_silently=False,
    )
    msg = EmailMessage(subject=subject, body=html, from_email=from_email, to=[to_email], connection=connection)
    msg.content_subtype = "html"
    msg.send(fail_silently=False)


def _send_html_email_admin_office(subject: str, to_email: str, html: str, text_fallback: str = " "):
    from_email = settings.EMAIL_ADMIN_OFFICE
    connection = get_connection(
        username=from_email,
        password=settings.EMAIL_CREDENTIALS[from_email],
        fail_silently=False,
    )
    msg = EmailMessage(subject=subject, body=html, from_email=from_email, to=[to_email], connection=connection)
    msg.content_subtype = "html"
    msg.send(fail_silently=False)


def _send_html_email_operations(subject: str, to_email: str, html: str, text_fallback: str = " "):
    from_email = settings.EMAIL_OPERATIONS
    connection = get_connection(
        username=from_email,
        password=settings.EMAIL_CREDENTIALS[from_email],
        fail_silently=False,
    )
    msg = EmailMessage(subject=subject, body=html, from_email=from_email, to=[to_email], connection=connection)
    msg.content_subtype = "html"
    msg.send(fail_silently=False)


def _send_html_email_billing(subject: str, to_email: str, html: str, text_fallback: str = " "):
    from_email = settings.EMAIL_BILLING
    connection = get_connection(
        username=from_email,
        password=settings.EMAIL_CREDENTIALS[from_email],
        fail_silently=False,
    )
    msg = EmailMessage(subject=subject, body=html, from_email=from_email, to=[to_email], connection=connection)
    msg.content_subtype = "html"
    msg.send(fail_silently=False)


# ----------------------------
# Pharmacy Page Logins
# ----------------------------
@ensure_csrf_cookie
def pharmacyLoginView(request):
    return render(request, 'pharmacyLogin.html')

@ensure_csrf_cookie
def pharmacyRegisterView(request):
    return render(
        request,
        "pharmacyRegister.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

@pharmacy_auth_required
def pharmacyDashboardView(request):
    return render(
        request,
        "pharmacyDashboard.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

@ensure_csrf_cookie
def pharmacyForgotPasswordView(request):
    return render(request, 'pharmacyForgotPassword.html')

@pharmacy_auth_required
def pharmacyOrdersView(request):
    return render(request, 'pharmacyOrders.html')

@pharmacy_auth_required
def pharmacyInvoicesView(request):
    return render(request, 'pharmacyInvoices.html')

@pharmacy_auth_required
def pharmacyCCPointsView(request):
    return render(request, 'pharmacyCCPoints.html')

@pharmacy_auth_required
def pharmacyHowToGuideView(request):
    return render(request, 'pharmacyHowToGuide.html')

@pharmacy_auth_required
def pharmacyProfileView(request):
    return render(
        request,
        "pharmacyProfile.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

def pharmacyTrialOnboarding(request):
    return render(request, 'pharmacyTrial.html')


# ----------------------------
# Driver Page Logins
# ----------------------------
@ensure_csrf_cookie
def driverLoginView(request):
    return render(request, 'driverLogin.html')

@driver_auth_required
def driverDashboardView(request):
    return render(request, 'driverDashboard.html')

@driver_auth_required
def driverAcceptedDeliveriesView(request):
    return render(request, 'driverAcceptedDeliveries.html')

@driver_auth_required
def driverFinancesView(request):
    return render(request, 'driverFinances.html')

@ensure_csrf_cookie
def driverForgotPasswordView(request):
    return render(request, 'driverForgotPassword.html')

@ensure_csrf_cookie
def driverRegisterView(request):
    return render(
        request,
        "driverRegister.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

@driver_auth_required
def driverIdentityView(request):
    return render(request, 'driverIdentity.html')

@driver_auth_required
def driverCCPointsView(request):
    return render(request, 'driverCCPoints.html')

# ----------------------------
# Admin Page Logins
# ----------------------------

@ensure_csrf_cookie
def adminLoginView(request):
    return render(request, 'adminLogin.html')

@admin_auth_required
def adminDashboardView(request):
    return render(request, 'adminDashboard.html')

@admin_auth_required
def adminOrdersView(request):
    return render(request, 'adminOrders.html')

@admin_auth_required
def adminPharmaciesView(request):
    return render(request, 'adminPharmacies.html')

@admin_auth_required
def adminOrdersView(request):
    return render(request, 'adminOrders.html')

@admin_auth_required
def adminInvoicesView(request):
    return render(request, 'adminInvoices.html')

@admin_auth_required
def adminSupportView(request):
    return render(request, 'adminSupport.html')

@admin_auth_required
def adminDriversView(request):
    return render(request, 'adminDrivers.html')

@admin_auth_required
def adminAnalyticsAndReportsView(request):
    return render(request, 'adminAnalyticsAndReports.html')

@admin_auth_required
def adminPaymentInformationView(request):
    return render(request, 'adminPaymentInformation.html')

@admin_auth_required
def adminPharmacyInformationView(request):
    return render(request, 'adminPharmacyInformation.html')

# ----------------------------
# General Page Logins
# ----------------------------
@user_auth_required
def contactAdminView(request):
    return render(request, 'contactAdmin.html')

def landingView(request):
    return render(request, 'landingPage.html')


@require_POST
@csrf_protect
def pharmacy_login_api(request):
    """
    Authenticates a pharmacy and sets JWT in an HttpOnly secure cookie.
    """

    # 1️⃣ Parse request body
    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")
    except Exception:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON"},
            status=400
        )

    if not email or not password:
        return JsonResponse(
            {"success": False, "message": "Email and password required"},
            status=400
        )

    # 2️⃣ Fetch pharmacy
    try:
        pharmacy = Pharmacy.objects.get(email=email)
    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Invalid credentials"},
            status=401
        )

    # 3️⃣ Verify password
    if not check_password(password, pharmacy.password):
        return JsonResponse(
            {"success": False, "message": "Invalid credentials"},
            status=401
        )

    # 4️⃣ Create JWT payload
    issued_at = timezone.now()  # UTC
    expires_at = issued_at + timedelta(hours=settings.JWT_EXPIRY_HOURS)

    payload = {
        "pharmacy_id": pharmacy.id,
        "email": pharmacy.email,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    # 5️⃣ Build response (NO token in JSON)
    response = JsonResponse({
        "success": True,
        "id": pharmacy.id,
        "expiresAt": timezone.localtime(
            expires_at,
            settings.USER_TIMEZONE
        ).isoformat(),
    })

    # 6️⃣ Set secure HttpOnly cookie
    response.set_cookie(
        key="authToken",
        value=token,
        max_age=settings.JWT_EXPIRY_HOURS * 60 * 60,
        httponly=True,                 # 🔐 JS cannot read
        secure=settings.SECURE_SSL_REDIRECT,  # 🔐 HTTPS only
        samesite="Lax",                # 🛡 CSRF protection
        path="/",
    )

    return response

@csrf_protect
@require_http_methods(["POST"])
@pharmacy_auth_required
def pharmacy_logout_api(request):
    response = JsonResponse({"success": True})

    # Clear server-managed/session cookies
    response.delete_cookie("authToken", path="/")
    response.delete_cookie("pharmacyId", path="/")
    response.delete_cookie("tokenExpiresAt", path="/")

    return response



def validate_address_city(address, city):
    """
    Validate that the address belongs to the provided city using Google Geocoding API.
    Returns True if valid, False otherwise.

    Prod upgrades:
    - Uses structured address_components (not string contains)
    - Works for any country
    - Adds timeout
    - Supports common "city-like" component types: locality, postal_town, admin_area_level_2
    """
    try:
        url = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            "address": f"{address}, {city}",
            "key": settings.GOOGLE_MAPS_API_KEY,
        }

        r = requests.get(url, params=params, timeout=5)
        data = r.json()

        if data.get("status") != "OK" or not data.get("results"):
            return False

        # Google’s best match
        result = data["results"][0]
        components = result.get("address_components", [])

        city_input = city.strip().lower()

        # Different countries represent “city” differently.
        city_types = {"locality", "postal_town", "administrative_area_level_2"}

        for comp in components:
            types = set(comp.get("types", []))
            if types.intersection(city_types):
                long_name = comp.get("long_name", "").strip().lower()
                short_name = comp.get("short_name", "").strip().lower()

                if city_input == long_name or city_input == short_name:
                    return True

        # Fallback (less strict): sometimes city isn't in components the way we expect
        formatted = result.get("formatted_address", "").lower()
        return city_input in formatted

    except requests.Timeout:
        return False
    except Exception:
        return False


def get_distance_km(pickup_address, pickup_city, drop_address, drop_city):
    """
    Calculate distance in km between pickup and drop using Google Distance Matrix.
    Returns (distance_km, error_message).
    """
    if not validate_address_city(pickup_address, pickup_city):
        return None, "Pickup address does not match the city"
    if not validate_address_city(drop_address, drop_city):
        return None, "Drop address does not match the city"

    full_pickup = f"{pickup_address}, {pickup_city}"
    full_drop = f"{drop_address}, {drop_city}"

    try:
        url = "https://maps.googleapis.com/maps/api/distancematrix/json"
        params = {
            "origins": full_pickup,
            "destinations": full_drop,
            "key": settings.GOOGLE_MAPS_API_KEY,
            "units": "metric",
        }

        data = requests.get(url, params=params, timeout=8).json()

        if data.get("status") != "OK":
            return 0, "Failed to calculate distance"

        element = data["rows"][0]["elements"][0]
        if element.get("status") != "OK":
            return 0, "Failed to calculate distance"

        distance_meters = element["distance"]["value"]
        return distance_meters / 1000, None

    except requests.Timeout:
        return 0, "Failed to calculate distance"
    except Exception:
        return 0, "Failed to calculate distance"



def create_order_tracking_entry(
    order_id,
    step="pending",
    performed_by=None,
    note=None,
    image_url=None,
    driver=None,
):
    """
    Create a tracking entry for an order.
    - Stores time in UTC (Django default)
    - Returns timestamp in USER_TIMEZONE
    """

    try:
        # Validate step
        valid_steps = {choice[0] for choice in OrderTracking.STEP_CHOICES}
        if step not in valid_steps:
            return {
                "success": False,
                "error": f"Invalid tracking step: {step}"
            }

        with transaction.atomic():
            order = DeliveryOrder.objects.select_related("pharmacy").get(id=order_id)

            tracking_entry = OrderTracking.objects.create(
                order=order,
                driver=driver,
                pharmacy=order.pharmacy,
                step=step,
                performed_by=performed_by or f"Pharmacy: {order.pharmacy.name}",
                note=note or f"Order {step}",
                image_url=image_url,
            )

        # Convert UTC → local timezone for response
        local_ts = timezone.localtime(
            tracking_entry.timestamp,
            settings.USER_TIMEZONE
        )

        return {
            "success": True,
            "tracking_id": tracking_entry.id,
            "step": tracking_entry.step,
            "performed_by": tracking_entry.performed_by,
            "timestamp": local_ts.isoformat(),  # LOCAL TIME ONLY
            "message": "Tracking entry created successfully"
        }

    except DeliveryOrder.DoesNotExist:
        return {
            "success": False,
            "error": f"Order with ID {order_id} not found"
        }

    except Exception:
        logger.exception(
            "Failed to create order tracking entry",
            extra={"order_id": order_id, "step": step}
        )
        return {
            "success": False,
            "error": "Failed to create tracking entry"
        }


@csrf_protect
@require_http_methods(["POST"])
@pharmacy_auth_required
def create_delivery_order(request):
    try:
        data = json.loads(request.body or "{}")

        # -----------------------------
        # Required fields
        # -----------------------------
        pharmacy_id = data.get("pharmacyId")
        pickup_address = data.get("pickupAddress")
        pickup_city = data.get("pickupCity")
        pickup_day = data.get("pickupDay")
        drop_address = data.get("dropAddress")
        drop_city = data.get("dropCity")

        # Optional existing fields
        customer_name = data.get("customerName")
        customer_phone = data.get("customerPhone")

        # Optional compliance fields
        signature_required = data.get("signatureRequired")
        id_verification_required = data.get("idVerificationRequired")
        alternate_contact = data.get("alternateContact")
        delivery_notes = data.get("deliveryNotes")

        # -----------------------------
        # Validation
        # -----------------------------
        if not all([
            pharmacy_id,
            pickup_address,
            pickup_city,
            pickup_day,
            drop_address,
            drop_city,
        ]):
            logger.info(
                "create_delivery_order: missing required fields | pharmacy_id=%s",
                pharmacy_id,
            )
            return JsonResponse(
                {"success": False, "error": "Missing required fields"},
                status=400
            )

        # -----------------------------
        # Pharmacy validation
        # -----------------------------
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)

        if request.pharmacy.id != pharmacy.id:
            logger.warning(
                "create_delivery_order: pharmacy mismatch | token=%s payload=%s",
                request.pharmacy.id,
                pharmacy.id,
            )
            return JsonResponse(
                {"success": False, "error": "Unauthorized pharmacy"},
                status=403
            )
        
        if not pharmacy.active:
          logger.warning("create_delivery_order: inactive pharmacy attempted order | pharmacy_id=%s",pharmacy.id,)
          return JsonResponse({"success": False, "error": "Your pharmacy account is currently inactive. Please contact support."}, status=403)

        # -----------------------------
        # Distance calculation
        # -----------------------------
        distance_km, error = get_distance_km(
            pickup_address,
            pickup_city,
            drop_address,
            drop_city,
        )

        if error:
            logger.warning(
                "create_delivery_order: distance error | pharmacy=%s error=%s",
                pharmacy.id,
                error,
            )
            return JsonResponse(
                {"success": False, "error": error},
                status=400
            )

        # -----------------------------
        # Rate calculation
        # -----------------------------
        rate_entry = (
            DeliveryDistanceRate.objects
            .filter(min_distance_km__lte=distance_km)
            .order_by("min_distance_km")
            .last()
        )

        rate = rate_entry.rate if rate_entry else 0

        # -----------------------------
        # Create kwargs
        # -----------------------------
        create_kwargs = {
            "pharmacy": pharmacy,
            "pickup_address": pickup_address,
            "pickup_city": pickup_city,
            "pickup_day": parse_date(pickup_day),
            "drop_address": drop_address,
            "drop_city": drop_city,
            "status": "pending",
            "rate": rate,
        }

        if customer_name:
            create_kwargs["customer_name"] = customer_name

        if customer_phone:
            create_kwargs["customer_phone"] = customer_phone

        if signature_required is not None:
            create_kwargs["signature_required"] = bool(signature_required)

        if id_verification_required is not None:
            create_kwargs["id_verification_required"] = bool(id_verification_required)

        if alternate_contact:
            create_kwargs["alternate_contact"] = alternate_contact

        if delivery_notes:
            create_kwargs["delivery_notes"] = delivery_notes

        # -----------------------------
        # Create order + tracking
        # -----------------------------
        with transaction.atomic():
            order = DeliveryOrder.objects.create(**create_kwargs)

            tracking_result = create_order_tracking_entry(
                order_id=order.id,
                step="pending",
                performed_by=f"Pharmacy: {pharmacy.name}",
                note="Order created and pending driver acceptance",
            )

        logger.info(
            "create_delivery_order: success | order_id=%s pharmacy=%s distance=%.2f rate=%s",
            order.id,
            pharmacy.id,
            distance_km,
            rate,
        )

        # -----------------------------
        # Response (UNCHANGED)
        # -----------------------------
        return JsonResponse(
            {
                "success": True,
                "orderId": order.id,
                "distance_km": distance_km,
                "rate": str(rate),
                "status": order.status,
                "customerName": order.customer_name,
                "customerPhone": order.customer_phone,
                "signatureRequired": order.signature_required,
                "idVerificationRequired": order.id_verification_required,
                "alternateContact": order.alternate_contact,
                "deliveryNotes": order.delivery_notes,
                "tracking_id": tracking_result.get("tracking_id"),
                "message": "Order and tracking created successfully",
            },
            status=201,
        )

    except Pharmacy.DoesNotExist:
        logger.warning(
            "create_delivery_order: pharmacy not found | pharmacy_id=%s",
            data.get("pharmacyId"),
        )
        return JsonResponse(
            {"success": False, "error": "Pharmacy not found"},
            status=404
        )

    except Exception:
        logger.exception("create_delivery_order: unhandled exception")
        return JsonResponse(
            {"success": False, "error": "Internal server error"},
            status=500
        )



def get_distance_km(pickup_address, pickup_city, drop_address, drop_city):
    """
    Calculate the distance in kilometers between pickup and drop locations 
    using Google Maps Distance Matrix API - WITHOUT separate address validation.
    If Google can calculate distance, the addresses are valid enough.
    """
    
    # Build full addresses
    full_pickup = f"{pickup_address}, {pickup_city}"
    full_drop = f"{drop_address}, {drop_city}"
    
    
    try:
        url = "https://maps.googleapis.com/maps/api/distancematrix/json"
        params = {
            "origins": full_pickup,
            "destinations": full_drop,
            "key": settings.GOOGLE_MAPS_API_KEY,
            "units": "metric"
        }
        
        response = requests.get(url, params=params)
        data = response.json()
        
        
        # Check overall API response
        if data.get('status') != 'OK':
            error_msg = f"Distance Matrix API error: {data.get('status', 'UNKNOWN')}"
            if 'error_message' in data:
                error_msg += f" - {data['error_message']}"
            return None, error_msg
        
        # Check if we have valid response structure
        rows = data.get('rows', [])
        if not rows or not rows[0].get('elements'):
            return None, "No route data returned from Google Maps"
            
        element = rows[0]['elements'][0]
        element_status = element.get('status')
        
        
        if element_status == 'OK':
            distance_meters = element.get('distance', {}).get('value')
            if distance_meters is None:
                return None, "Distance data not found in response"
                
            distance_km = distance_meters / 1000
            duration_text = element.get('duration', {}).get('text', 'Unknown')
            
            return distance_km, None
            
        elif element_status == 'NOT_FOUND':
            return None, "One or both addresses could not be found by Google Maps"
        elif element_status == 'ZERO_RESULTS':
            return None, "No route could be found between the addresses"
        elif element_status == 'MAX_WAYPOINTS_EXCEEDED':
            return None, "Too many waypoints in request"
        elif element_status == 'MAX_ROUTE_LENGTH_EXCEEDED':
            return None, "Route is too long"
        elif element_status == 'INVALID_REQUEST':
            return None, "Invalid request to Google Maps"
        else:
            return None, f"Route calculation failed with status: {element_status}"
            
    except KeyError as e:
        error_msg = f"Unexpected response format from Google Maps API: missing {e}"
        return None, error_msg
    except Exception as e:
        error_msg = f"Distance calculation failed: {str(e)}"
        import traceback
        traceback.print_exc()
        return None, error_msg


@require_GET
@csrf_protect
@pharmacy_auth_required
def get_delivery_rate(request):
    """
    Returns delivery distance (km) and rate for a pickup & drop address.

    Auth:
    - Requires valid HttpOnly JWT cookie (pharmacy)
    - CSRF protected

    Input (unchanged):
    - pickupAddress
    - pickupCity
    - dropAddress
    - dropCity

    Output (unchanged):
    - success
    - distance_km
    - rate
    """
    try:
        pickup_address = request.GET.get("pickupAddress")
        pickup_city = request.GET.get("pickupCity")
        drop_address = request.GET.get("dropAddress")
        drop_city = request.GET.get("dropCity")

        # 1️⃣ Validate required fields
        if not all([pickup_address, pickup_city, drop_address, drop_city]):
            return JsonResponse(
                {"success": False, "error": "Missing required fields"},
                status=400
            )

        # 2️⃣ Distance calculation (internally validates addresses)
        distance_km, error = get_distance_km(
            pickup_address,
            pickup_city,
            drop_address,
            drop_city
        )

        if error:
            return JsonResponse(
                {"success": False, "error": error},
                status=400
            )

        # 3️⃣ Resolve rate slab
        rate_entry = (
            DeliveryDistanceRate.objects
            .filter(min_distance_km__lte=distance_km)
            .order_by("min_distance_km")
            .last()
        )

        rate = float(rate_entry.rate) if rate_entry else 0.0

        # 4️⃣ Success response (unchanged)
        return JsonResponse({
            "success": True,
            "distance_km": round(distance_km, 2),
            "rate": rate
        })

    except Exception:
        # ❗ Log internally only (avoid leaking stacktrace to client)
        import traceback
        traceback.print_exc()

        return JsonResponse(
            {"success": False, "error": "Server error"},
            status=500
        )




@require_GET
@csrf_protect  
@pharmacy_auth_required
def get_pharmacy_orders(request, pharmacy_id):
    """
    Fetch latest 10 orders for a pharmacy.
    - Authenticated via JWT
    - CSRF protected
    - Pharmacy access enforced
    """

    try:
        auth_pharmacy_id = request.pharmacy.id  
        
        if int(auth_pharmacy_id) != int(pharmacy_id):
            logger.warning(
                "Unauthorized pharmacy access attempt",
                extra={
                    "auth_pharmacy_id": auth_pharmacy_id,
                    "requested_pharmacy_id": pharmacy_id,
                },
            )
            return JsonResponse({"error": "Unauthorized access"}, status=403)

        # ✅ Use the pharmacy object already loaded by decorator
        pharmacy = request.pharmacy  # No need to query again
        
        # ✅ PROD ordering: newest by created_at (then id as tie-breaker)
        orders = (
            DeliveryOrder.objects
            .filter(pharmacy=pharmacy)
            .order_by("-created_at", "-id")[:10]
            .values(
                "id",
                "customer_name",
                "pickup_address",
                "pickup_city",
                "drop_address",
                "drop_city",
                "pickup_day",
                "rate",
                "status",
            )
        )

        logger.info(
            "Fetched pharmacy orders",
            extra={"pharmacy_id": pharmacy_id, "count": len(orders)},
        )

        return JsonResponse(list(orders), safe=False, status=200)

    except AttributeError as e:
        # Catch if request.pharmacy doesn't exist
        logger.error(f"Pharmacy attribute missing: {e}")
        return JsonResponse({"error": "Authentication error"}, status=401)

    except Exception:
        logger.exception("Failed to fetch pharmacy orders", extra={"pharmacy_id": pharmacy_id})
        return JsonResponse({"error": "Internal server error"}, status=500)



class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)


@csrf_protect
@require_http_methods(["GET"])
@pharmacy_auth_required
def pharmacy_orders_api(request, pharmacy_id):
    """
    Fetch all orders for a pharmacy with tracking timeline and images.
    - Authenticated pharmacy only
    - CSRF protected
    - Time returned in USER_TIMEZONE
    """

    try:
        # --------------------------------------------------
        # Pharmacy validation (ownership enforced)
        # --------------------------------------------------
        pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

        if request.pharmacy.id != pharmacy.id:
            logger.warning(
                "Unauthorized pharmacy access attempt",
                extra={
                    "request_pharmacy": request.pharmacy.id,
                    "target_pharmacy": pharmacy.id,
                },
            )
            return JsonResponse(
                {"success": False, "error": "Unauthorized access"},
                status=403,
            )

        # --------------------------------------------------
        # Fetch orders (efficient)
        # --------------------------------------------------
        orders = (
            DeliveryOrder.objects
            .filter(pharmacy=pharmacy)
            .select_related("driver")
            .prefetch_related("tracking_entries", "images")
            .order_by("-created_at")
        )

        orders_data = []

        # --------------------------------------------------
        # Iterate orders
        # --------------------------------------------------
        for order in orders:

            # -----------------------------
            # Tracking timeline (LOCAL TIME)
            # -----------------------------
            tracking_entries = []

            for entry in order.tracking_entries.all():
                local_ts = timezone.localtime(
                    entry.timestamp,
                    settings.USER_TIMEZONE
                ) if entry.timestamp else None

                tracking_entries.append({
                    "step": entry.step,
                    "performed_by": entry.performed_by,
                    "timestamp": local_ts.strftime("%Y-%m-%d %H:%M:%S") if local_ts else None,
                    "note": entry.note,
                    "image_url": entry.image_url,
                })

            # -----------------------------
            # Images grouped by stage
            # -----------------------------
            images_by_stage = {
                "handover": [],
                "pickup": [],
                "delivered": [],
            }

            for image in order.images.all():
                uploaded_local = timezone.localtime(
                    image.uploaded_at,
                    settings.USER_TIMEZONE
                )

                images_by_stage[image.stage].append({
                    "image_url": image.image_url,
                    "uploaded_at": uploaded_local.strftime("%Y-%m-%d %H:%M:%S"),
                })

            total_images = sum(len(v) for v in images_by_stage.values())

            # -----------------------------
            # Progress calculation
            # -----------------------------
            progress_map = {
                "pending": 25,
                "accepted": 50,
                "picked_up": 75,
                "delivered": 100,
                "cancelled": 0,
            }

            # -----------------------------
            # Convert order timestamps
            # -----------------------------
            created_local = timezone.localtime(
                order.created_at,
                settings.USER_TIMEZONE
            )

            updated_local = timezone.localtime(
                order.updated_at,
                settings.USER_TIMEZONE
            )

            delivered_local = timezone.localtime(
                order.delivered_at,
                settings.USER_TIMEZONE
            )

            # -----------------------------
            # Core order payload (UNCHANGED)
            # -----------------------------
            order_data = {
                "id": order.id,
                "pickup_address": order.pickup_address,
                "pickup_city": order.pickup_city,
                "pickup_day": order.pickup_day.strftime("%Y-%m-%d"),
                "drop_address": order.drop_address,
                "drop_city": order.drop_city,
                "status": order.status,
                "rate": order.rate,
                "customer_name": order.customer_name,
                "customer_phone": order.customer_phone,
                "alternate_contact": order.alternate_contact,
                "signature_required": order.signature_required,
                "signature_ack_url": order.signature_ack_url,
                "id_verification_required": order.id_verification_required,
                "id_verified": order.id_verified,
                "delivery_notes": order.delivery_notes,
                "driver_notes" : order.driver_notes,
                "created_at": created_local.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": updated_local.strftime("%Y-%m-%d %H:%M:%S"),
                "delivered_at": delivered_local.strftime("%Y-%m-%d %H:%M:%S"),
                "is_delivered" : order.is_delivered,
                "driver_id": order.driver.id if order.driver else None,
                "driver_name": order.driver.name if order.driver else None,
                "progress_percentage": progress_map.get(order.status, 0),
                "total_images": total_images,
                "timeline": tracking_entries,
                "images": images_by_stage,
            }

            # -----------------------------
            # Driver details (if exists)
            # -----------------------------
            if order.driver:
                order_data["driver"] = {
                    "id": order.driver.id,
                    "name": order.driver.name,
                    "phone_number": order.driver.phone_number,
                    "email": order.driver.email,
                    "vehicle_number": order.driver.vehicle_number,
                    "identity_url": order.driver.identity_url,
                    "active": order.driver.active,
                }

            orders_data.append(order_data)

        # --------------------------------------------------
        # Final response (UNCHANGED)
        # --------------------------------------------------
        response_data = {
            "success": True,
            "pharmacy_id": pharmacy.id,
            "pharmacy_name": pharmacy.name,
            "total_orders": len(orders_data),
            "orders": orders_data,
        }

        logger.info(
            "Pharmacy orders fetched",
            extra={
                "pharmacy_id": pharmacy.id,
                "order_count": len(orders_data),
            },
        )

        return JsonResponse(response_data, encoder=DecimalEncoder, safe=False)

    except Exception:
        logger.exception(
            "Failed to fetch pharmacy orders",
            extra={"pharmacy_id": pharmacy_id},
        )
        return JsonResponse(
            {"success": False, "error": "Internal server error"},
            status=500,
        )

@csrf_protect
@require_http_methods(["POST"])
@pharmacy_auth_required
def upload_handover_image_api(request):
    try:
        # Debug logging (removed PII)
        logger.info(f"Upload request received with {len(request.FILES)} file(s)")
        
        # Validate required fields
        if 'image' not in request.FILES:
            logger.error("No image file in request")
            return JsonResponse({
                'success': False,
                'error': 'No image file provided'
            }, status=400)
        
        order_number = request.POST.get('order_number')
        pharmacy_id = request.POST.get('pharmacy_id')
        pharmacy_name = request.POST.get('pharmacy_name')
        driver_id = request.POST.get('driver_id')
        
        logger.info(f"Processing upload for order: {order_number}")
        
        if not all([order_number, pharmacy_id, pharmacy_name]):
            logger.error("Missing required fields")
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields: order_number, pharmacy_id, pharmacy_name'
            }, status=400)
        
        # Validate pharmacy exists
        try:
            pharmacy = request.pharmacy
            if str(pharmacy.id) != str(pharmacy_id):
                logger.warning(
                    "Unauthorized pharmacy attempting upload",
                    extra={"auth_pharmacy_id": pharmacy.id, "payload_pharmacy_id": pharmacy_id}
                )
                return JsonResponse(
                    {"success": False, "error": "Unauthorized pharmacy"},
                    status=403
                )
            logger.info(f"Pharmacy validated: ID {pharmacy.id}")
        except Exception as e:
            logger.error(f"Pharmacy lookup failed: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Pharmacy not found'
            }, status=404)
        
        # Validate order exists and belongs to pharmacy
        try:
            order = get_object_or_404(DeliveryOrder, id=order_number, pharmacy=pharmacy)
            logger.info(f"Order found: #{order.id}")
        except Exception as e:
            logger.error(f"Order lookup failed: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Order not found or does not belong to this pharmacy'
            }, status=404)
        
        # Validate driver if driver_id is provided and not empty
        driver = None
        if driver_id and driver_id not in ['null', '', 'undefined']:
            try:
                driver = get_object_or_404(Driver, id=driver_id)
                logger.info(f"Driver validated: ID {driver.id}")
            except Exception as e:
                logger.warning(f"Driver lookup failed for ID {driver_id}: {e}")
                driver = None
        else:
            logger.info("No driver_id provided or driver_id is empty/null")
        
        # Get the uploaded image
        image_file = request.FILES['image']
        logger.info(f"Image file received: size={image_file.size} bytes, type={image_file.content_type}")
        
        # Validate image file
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
        if '.' in image_file.name:
            file_extension = '.' + image_file.name.split('.')[-1].lower()
        else:
            logger.error("File has no extension")
            return JsonResponse({
                'success': False,
                'error': 'Invalid file - no extension found'
            }, status=400)
        
        if file_extension not in allowed_extensions:
            logger.error(f"Invalid file extension: {file_extension}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid file type. Allowed: jpg, jpeg, png, gif'
            }, status=400)
        
        # Create filename
        safe_pharmacy_name = "".join(c for c in pharmacy.name if c.isalnum() or c in ('-', '_')).strip()
        filename = f"{order_number}_{pharmacy_id}_{safe_pharmacy_name}_handover{file_extension}"
        # blob_name = f"Proof/{filename}"
        blob_name = f"{settings.GCP_PROOF_FOLDER.rstrip('/')}/{filename}"
        
        logger.info(f"Generated blob path: {blob_name}")
        
        # Initialize GCP Storage client
        try:
            from google.cloud import storage
            from google.oauth2 import service_account
            
            logger.info("Initializing Google Cloud Storage client")
            
            gcp_key_path = settings.GCP_KEY_PATH
            
            if not os.path.exists(gcp_key_path):
                logger.error(f"GCP key file not found at configured path")
                return JsonResponse({
                    'success': False,
                    'error': 'GCP service account key file not found'
                }, status=500)
            
            credentials = service_account.Credentials.from_service_account_file(settings.GCP_KEY_PATH)
            client = storage.Client(credentials=credentials)
            bucket = client.bucket(settings.GCP_BUCKET_NAME)
            blob = bucket.blob(blob_name)
            
            logger.info("Google Cloud client initialized successfully")
            
            # Reset file pointer to beginning
            image_file.seek(0)
            
            # Upload the file
            logger.info(f"Starting upload to GCS")
            blob.upload_from_file(
                image_file,
                content_type=image_file.content_type
            )
            logger.info("Upload to GCS completed")
            
            public_url = f"https://storage.googleapis.com/{bucket.name}/{blob_name}"
            logger.info("Public URL generated successfully")
            
        except ImportError as e:
            logger.error(f"Missing Google Cloud libraries: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Google Cloud Storage libraries not installed. Run: pip install google-cloud-storage'
            }, status=500)
            
        except Exception as gcp_error:
            logger.error(f"GCP upload error: {gcp_error}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to upload to GCP: {str(gcp_error)}'
            }, status=500)
        
        # ✅ WRAP ALL DATABASE OPERATIONS IN ATOMIC TRANSACTION
        try:
            with transaction.atomic():
                # Save OrderImage record
                order_image = OrderImage.objects.create(
                    order=order,
                    image_url=public_url,
                    stage='handover'
                )
                logger.info(f"OrderImage created with ID: {order_image.id}")
                
                # Add tracking entry for handover
                performed_by = f"Pharmacy: {pharmacy.name}"
                
                tracking_entry = OrderTracking.objects.create(
                    order=order,
                    pharmacy=pharmacy,
                    driver=driver,
                    step='handover',
                    performed_by=performed_by,
                    note=f"Handover image uploaded: {filename}",
                    image_url=public_url
                )
                logger.info(f"OrderTracking created with ID: {tracking_entry.id}")
                
                # Update order status to picked_up
                order.status = 'picked_up'
                order.save()
                logger.info(f"Order status updated to: {order.status}")
                
        except Exception as db_error:
            logger.error(f"Database transaction failed: {db_error}")
            # If DB transaction fails, we should ideally delete the uploaded image from GCS
            try:
                blob.delete()
                logger.info("Rolled back GCS upload due to database failure")
            except Exception as cleanup_error:
                logger.error(f"Failed to cleanup GCS blob after DB error: {cleanup_error}")
            
            return JsonResponse({
                'success': False,
                'error': f'Failed to save order data: {str(db_error)}'
            }, status=500)
        
        # Send handover confirmation email to driver (outside transaction - non-critical)
        if driver and driver.email:
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                logo_url = settings.LOGO_URL
                
                pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

                html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Package Handover Confirmation • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Order #{order.id} handed over by pharmacy — ready for pickup.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Package Ready for Pickup
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Package handed over by pharmacy! 📦
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{driver.name}</strong>, the pharmacy <strong>{pharmacy.name}</strong> has confirmed handover 
                  of order <strong>#{order.id}</strong> to you. The package is now ready for delivery to the customer.
                </p>

                <div style="margin:18px 0;background:#eff6ff;border:1px solid #3b82f6;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#1e40af;">
                    ✅ Status: <strong>Picked Up</strong> — Ready for delivery
                  </p>
                </div>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📦 Order Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Order ID:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{order.id}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Customer:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.customer_name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivery Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        ${order.rate}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pickup Date:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pickup_date_str}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Handed Over At:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {now_str}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏢 Pickup Location (Pharmacy)
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pharmacy Name:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Phone:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.phone_number}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Address:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.store_address}, {pharmacy.city}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📸 Handover Proof Photo
                  </p>
                  <div style="margin:12px 0;text-align:center;">
                    <img src="{public_url}" 
                         alt="Handover Proof" 
                         style="max-width:100%;height:auto;border-radius:8px;border:2px solid #e5e7eb;">
                  </div>
                  <p style="margin:8px 0 0;font:400 12px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;text-align:center;">
                    Handover verification photo taken by pharmacy
                  </p>
                </div>

                <div style="margin:18px 0;background:#fef3c7;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏠 Delivery Destination
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    Customer: {order.customer_name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_city}
                  </p>
                </div>

                <div style="margin:18px 0;background:#fef2f2;border:1px solid #ef4444;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    ⚠️ Next Steps
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    Please proceed with the delivery to the customer at your earliest convenience. Remember to take a delivery proof photo upon completion.
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For any questions or issues, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for being a valued Delivery Partner with {settings.COMPANY_OPERATING_NAME}!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Package Handover Confirmation - {settings.COMPANY_OPERATING_NAME}\n\n"
                    f"Hello {driver.name},\n\n"
                    f"The pharmacy {pharmacy.name} has confirmed handover of order #{order.id} to you. "
                    f"The package is now ready for delivery to the customer.\n\n"
                    f"ORDER INFORMATION:\n"
                    f"- Order ID: #{order.id}\n"
                    f"- Customer: {order.customer_name}\n"
                    f"- Delivery Rate: ${order.rate}\n"
                    f"- Pickup Date: {pickup_date_str}\n"
                    f"- Handed Over At: {now_str}\n\n"
                    f"PICKUP LOCATION (PHARMACY):\n"
                    f"- Name: {pharmacy.name}\n"
                    f"- Phone: {pharmacy.phone_number}\n"
                    f"- Address: {pharmacy.store_address}, {pharmacy.city}\n\n"
                    f"DELIVERY DESTINATION:\n"
                    f"- Customer: {order.customer_name}\n"
                    f"- Address: {order.drop_address}\n"
                    f"- City: {order.drop_city}\n\n"
                    f"Handover Proof Photo: {public_url}\n\n"
                    f"Please proceed with the delivery to the customer. Remember to take a delivery proof photo upon completion.\n"
                )

                _send_html_email_operations(
                    subject=f"Package Handed Over • Order #{order.id} Ready for Delivery",
                    to_email=driver.email,
                    html=html,
                    text_fallback=text,
                )
                logger.info(f"Handover confirmation email sent to driver ID: {driver.id}")
            except Exception as email_error:
                logger.error(f"Failed to send handover email to driver: {email_error}")
                # Don't fail the entire request if email fails
                pass
        
        logger.info("Upload process completed successfully")
        
        return JsonResponse({
            'success': True,
            'message': 'Handover image uploaded successfully',
            'data': {
                'order_id': order.id,
                'pharmacy_id': pharmacy.id,
                'pharmacy_name': pharmacy.name,
                'driver_id': driver.id if driver else None,
                'driver_name': driver.name if driver else None,
                'image_url': public_url,
                'filename': filename,
                'order_status': order.status,
                'tracking_entry_id': tracking_entry.id,
                'uploaded_at': (timezone.localtime(order_image.uploaded_at, settings.USER_TIMEZONE)).isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Unexpected error in upload_handover_image_api: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred. Please try again later.'
        }, status=500)


# @require_POST
# @csrf_protect
# def driver_login(request):
#     """
#     Authenticates a driver and sets JWT in an HttpOnly secure cookie.
#     """

#     # 1️⃣ Parse request body
#     try:
#         data = json.loads(request.body)
#         email = data.get("email")
#         password = data.get("password")
#     except Exception:
#         return JsonResponse(
#             {"success": False, "message": "Invalid JSON"},
#             status=400
#         )

#     if not email or not password:
#         return JsonResponse(
#             {"success": False, "message": "Email and password required"},
#             status=400
#         )

#     # 2️⃣ Fetch driver
#     try:
#         driver = Driver.objects.get(email=email, active=True)
#     except Driver.DoesNotExist:
#         return JsonResponse(
#             {"success": False, "message": "Invalid credentials"},
#             status=401
#         )

#     # 3️⃣ Verify password (hashed only)
#     if not check_password(password, driver.password):
#         return JsonResponse(
#             {"success": False, "message": "Invalid credentials"},
#             status=401
#         )

#     # 4️⃣ Create JWT payload
#     issued_at = timezone.now()  # UTC
#     expires_at = issued_at + timedelta(hours=settings.JWT_EXPIRY_HOURS)

#     payload = {
#         "driver_id": driver.id,
#         "email": driver.email,
#         "iat": int(issued_at.timestamp()),
#         "exp": int(expires_at.timestamp()),
#     }

#     token = jwt.encode(
#         payload,
#         settings.JWT_SECRET_KEY,
#         algorithm=settings.JWT_ALGORITHM
#     )

#     # 5️⃣ Build response (NO token in JSON)
#     response = JsonResponse({
#         "success": True,
#         "id": driver.id,
#         "expiresAt": timezone.localtime(
#             expires_at,
#             settings.USER_TIMEZONE
#         ).isoformat(),
#     })

#     # 6️⃣ Set secure HttpOnly cookie
#     response.set_cookie(
#         key="authToken",
#         value=token,
#         max_age=settings.JWT_EXPIRY_HOURS * 60 * 60,
#         httponly=True,                         # 🔐 JS cannot read
#         secure=settings.SECURE_SSL_REDIRECT,  # 🔐 HTTPS only
#         samesite="Lax",                        # 🛡 CSRF protection
#         path="/",
#     )

#     return response


@require_POST
@csrf_protect
def driver_login(request):
    """
    Authenticates a driver and sets JWT in an HttpOnly secure cookie.
    
    NOTE: Inactive drivers CAN login (to view their account/history)
          but CANNOT accept new orders (enforced in assign_driver API).
    """

    # 1️⃣ Parse request body
    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")
    except Exception:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON"},
            status=400
        )

    if not email or not password:
        return JsonResponse(
            {"success": False, "message": "Email and password required"},
            status=400
        )

    # 2️⃣ Fetch driver (REMOVED active=True check)
    try:
        driver = Driver.objects.get(email=email)  # ✅ Allow both active and inactive
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Invalid credentials"},
            status=401
        )

    # 3️⃣ Verify password (hashed only)
    if not check_password(password, driver.password):
        return JsonResponse(
            {"success": False, "message": "Invalid credentials"},
            status=401
        )

    # 4️⃣ Create JWT payload (include active status for frontend)
    issued_at = timezone.now()  # UTC
    expires_at = issued_at + timedelta(hours=settings.JWT_EXPIRY_HOURS)

    payload = {
        "driver_id": driver.id,
        "email": driver.email,
        "active": driver.active,  # ✅ Include active status in JWT
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    # 5️⃣ Build response (include active status)
    response = JsonResponse({
        "success": True,
        "id": driver.id,
        "active": driver.active,  # ✅ Let frontend know if driver is inactive
        "expiresAt": timezone.localtime(
            expires_at,
            settings.USER_TIMEZONE
        ).isoformat(),
    })

    # 6️⃣ Set secure HttpOnly cookie
    response.set_cookie(
        key="authToken",
        value=token,
        max_age=settings.JWT_EXPIRY_HOURS * 60 * 60,
        httponly=True,                         # 🔐 JS cannot read
        secure=settings.SECURE_SSL_REDIRECT,  # 🔐 HTTPS only
        samesite="Lax",                        # 🛡 CSRF protection
        path="/",
    )

    return response

    
@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def driver_logout_api(request):
    response = JsonResponse({"success": True})

    # Clear server-managed/session cookies
    response.delete_cookie("authToken", path="/")
    response.delete_cookie("driverId", path="/")
    response.delete_cookie("tokenExpiresAt", path="/")

    return response



@csrf_protect
@require_http_methods(["GET"])
@driver_auth_required
def get_pending_orders(request):
    """
    Returns all pending delivery orders.
    - DB timestamps are stored in UTC
    - API converts timestamps to settings.USER_TIMEZONE
    - Requires authenticated driver (JWT in HttpOnly cookie)
    """

    orders = (
        DeliveryOrder.objects
        .select_related("pharmacy", "driver")
        .filter(status="pending")
        .order_by("created_at")
    )

    data = []

    for order in orders:
        pharmacy = order.pharmacy
        store_timing = None

        # ----------------------------
        # Business-hours logic (date-only, timezone-independent)
        # ----------------------------
        if pharmacy and pharmacy.business_hours and order.pickup_day:
            day_key = order.pickup_day.strftime("%a")  # Mon, Tue, Wed
            day_hours = pharmacy.business_hours.get(day_key)

            if not day_hours or day_hours == "closed":
                store_timing = {
                    "day": day_key,
                    "status": "closed"
                }
            else:
                store_timing = {
                    "day": day_key,
                    "status": "open",
                    "open": day_hours.get("open"),
                    "close": day_hours.get("close")
                }

        # ----------------------------
        # ⏰ TIMEZONE CONVERSION (UTC → USER_TIMEZONE)
        # ----------------------------
        created_local = timezone.localtime(
            order.created_at,
            settings.USER_TIMEZONE
        )
        updated_local = timezone.localtime(
            order.updated_at,
            settings.USER_TIMEZONE
        )

        data.append({
            "id": order.id,
            "pharmacy": pharmacy.name if pharmacy else None,
            "driver": order.driver.name if order.driver else None,

            "pickup_address": order.pickup_address,
            "pickup_city": order.pickup_city,
            "pickup_day": order.pickup_day.strftime("%Y-%m-%d"),

            "drop_address": order.drop_address,
            "drop_city": order.drop_city,

            "status": order.status,
            "rate": str(order.rate),

            "store_timing_for_pickup_day": store_timing,

            # Local time output (same format as before)
            "created_at": created_local.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": updated_local.strftime("%Y-%m-%d %H:%M:%S"),
        })

    return JsonResponse({"orders": data}, status=200)


@require_http_methods(["POST"])
@csrf_protect
@driver_auth_required
def assign_driver(request):
        try:
            body = json.loads(request.body.decode("utf-8"))
            order_id = body.get("orderId")
            driver_id = body.get("driverId")

            if not order_id or not driver_id:
                return JsonResponse({"error": "orderId and driverId are required"}, status=400)

            # Fetch order & driver
            order = DeliveryOrder.objects.get(id=order_id)
            driver = Driver.objects.get(id=driver_id)

            # ✅ CHECK IF DRIVER IS ACTIVE
            if not driver.active:
                return JsonResponse({
                    "success": False,
                    "error": f"Driver {driver.name} is currently inactive and cannot accept orders"
                }, status=400)

            # Update order
            order.driver = driver
            order.status = "accepted"
            order.save()

            # Log in OrderTracking
            tracking = OrderTracking.objects.create(
                order=order,
                driver=driver,
                pharmacy=order.pharmacy,
                step="accepted",
                performed_by=f"Driver: {driver.name}",
                note=f"{order.pharmacy.id}_{order.id}_{driver.id}_Accepted",
                image_url=None
            )

            # ---- Send order acceptance confirmation email to driver ----
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                now_utc = timezone.now()
                now_local = now_utc.astimezone(settings.USER_TIMEZONE)
                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                logo_url = settings.LOGO_URL
                
                # Format pickup date
                pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

                # Calculate estimated delivery time (pickup day + 1 hour as example)
                # You can adjust this logic based on your business rules
                estimated_delivery = "Same day delivery"

                html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Accepted • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Order #{order.id} confirmed — ready for pickup and delivery.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Order Accepted
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {driver.name}, order confirmed!
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  You've successfully accepted delivery order <strong>#{order.id}</strong>. Please review the details below 
                  and ensure timely pickup and delivery. Safe travels!
                </p>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📦 Order Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Order ID:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{order.id}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pharmacy:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.pharmacy.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Customer:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.customer_name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivery Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        ${order.rate}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pickup Date:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pickup_date_str}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#fff7ed;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📍 Pickup Location
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    {order.pharmacy.name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.pickup_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.pickup_city}
                  </p>
                  <p style="margin:8px 0 0;font:400 12px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                    📞 {order.pharmacy.phone_number}
                  </p>
                </div>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏠 Delivery Location
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    Customer: {order.customer_name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_city}
                  </p>
                  <p style="margin:8px 0 0;font:400 12px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                    ⏱️ {estimated_delivery}
                  </p>
                </div>

                <div style="margin:18px 0;background:#fef3c7;border-left:3px solid #f59e0b;border-radius:8px;padding:14px 16px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#92400e;">
                    ⚠️ Important: Please capture photos at pickup and delivery for order verification and tracking.
                  </p>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Order accepted on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Questions or issues with this delivery? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Drive safe and thank you for being part of the {settings.COMPANY_OPERATING_NAME} team!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Order Accepted - {settings.COMPANY_OPERATING_NAME}\n\n"
                    f"Hi {driver.name},\n\n"
                    f"You've successfully accepted delivery order #{order.id}.\n\n"
                    f"ORDER DETAILS:\n"
                    f"- Pharmacy: {order.pharmacy.name}\n"
                    f"- Customer: {order.customer_name}\n"
                    f"- Delivery Rate: ${order.rate}\n"
                    f"- Pickup Date: {pickup_date_str}\n\n"
                    f"PICKUP LOCATION:\n"
                    f"{order.pharmacy.name}\n"
                    f"{order.pickup_address}\n"
                    f"{order.pickup_city}\n"
                    f"Phone: {order.pharmacy.phone_number}\n\n"
                    f"DELIVERY LOCATION:\n"
                    f"Customer: {order.customer_name}\n"
                    f"{order.drop_address}\n"
                    f"{order.drop_city}\n\n"
                    f"Remember to capture photos at pickup and delivery.\n\n"
                    f"Questions? Contact operations at {settings.EMAIL_OPERATIONS}\n"
                )

                _send_html_email_operations(
                    subject=f"Order #{order.id} Accepted • {settings.COMPANY_OPERATING_NAME}",
                    to_email=driver.email,
                    html=html,
                    text_fallback=text,
                )
            except Exception as e:
                print(f"ERROR sending driver email: {str(e)}")
                import traceback
                traceback.print_exc()

            # ---- Send order assignment notification email to pharmacy ----
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                now_utc = timezone.now() 
                now_local = now_utc.astimezone(settings.USER_TIMEZONE)
                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                logo_url = settings.LOGO_URL

                pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")
              
                estimated_delivery = "Same day delivery"

                pharmacy_html = f"""\
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Delivery Partner Assigned • {settings.COMPANY_OPERATING_NAME}</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                @media (prefers-color-scheme: dark) {{
                    body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
                    .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
                    .muted {{ color: #94a3b8 !important; }}
                }}
                </style>
            </head>
            <body style="margin:0;padding:0;background:#f4f7f9;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
                <tr>
                    <td align="center">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
                        <tr>
                        <td style="background:{brand_primary};padding:18px 20px;">
                            <table width="100%" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                                <td align="left">
                                <img src="{logo_url}" alt="{settings.COMPANY_OPERATING_NAME}" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                                </td>
                                <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                                Delivery Partner Assigned
                                </td>
                            </tr>
                            </table>
                        </td>
                        </tr>
                        
                        <tr>
                        <td style="padding:28px 24px 6px;">
                            <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                            Great news! Delivery Partner assigned to your order
                            </h1>
                            <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                            Hello <strong>{order.pharmacy.name}</strong>, your delivery order <strong>#{order.id}</strong> has been accepted by a delivery partner and is now in progress.
                            </p>
                            
                            <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:14px 18px;">
                            <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                                ✓ Order Status: <strong>Accepted</strong> — Delivery Partner will arrive for pickup soon.
                            </p>
                            </div>
                            
                            <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                            <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                                📦 Order Information
                            </p>
                            <table width="100%" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Order ID:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    #{order.id}
                                </td>
                                </tr>
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Customer:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    {order.customer_name}
                                </td>
                                </tr>
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Delivery Rate:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    ${order.rate}
                                </td>
                                </tr>
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Pickup Date:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    {pickup_date_str}
                                </td>
                                </tr>
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Estimated Delivery:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    {estimated_delivery}
                                </td>
                                </tr>
                            </table>
                            </div>
                            
                            <div style="margin:18px 0;background:#eff6ff;border:1px solid #3b82f6;border-radius:12px;padding:16px 18px;">
                            <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                                🚗 Delivery Partner Information
                            </p>
                            <table width="100%" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Partner Name:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    {driver.name}
                                </td>
                                </tr>
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Partner Phone:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    {driver.phone_number}
                                </td>
                                </tr>
                                <tr>
                                <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    Vehicle Number:
                                </td>
                                <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                    {driver.vehicle_number or 'N/A'}
                                </td>
                                </tr>
                            </table>
                            </div>
                            
                            <div style="margin:18px 0;background:#fff7ed;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                            <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                                📍 Pickup Location
                            </p>
                            <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                {order.pharmacy.name}
                            </p>
                            <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                                {order.pickup_address}
                            </p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                                {order.pickup_city}
                            </p>
                            </div>
                            
                            <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:16px 18px;">
                            <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                                🏠 Delivery Location
                            </p>
                            <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                                Customer: {order.customer_name}
                            </p>
                            <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                                {order.drop_address}
                            </p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                                {order.drop_city}
                            </p>
                            </div>
                            
                            <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                            Delivery Partner assigned on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
                            </p>
                            
                            <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                            <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                            Track your order in real-time through your dashboard. Questions? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                            </p>
                        </td>
                        </tr>
                        
                        <tr>
                        <td style="padding:0 24px 24px;">
                            <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                            <tr>
                                <td style="padding:12px 16px;">
                                <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                                    Thank you for trusting {settings.COMPANY_OPERATING_NAME} with your deliveries!
                                </p>
                                </td>
                            </tr>
                            </table>
                        </td>
                        </tr>

                    </table>
                    
                    <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
                        © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
                    </p>
                    </td>
                </tr>
                </table>
            </body>
            </html>
            """
                pharmacy_text = (
                    f"Delivery Partner Assigned - {settings.COMPANY_OPERATING_NAME}\n\n"
                    f"Hello {order.pharmacy.name},\n\n"
                    f"Your delivery order #{order.id} has been accepted by a delivery partner.\n\n"
                    f"ORDER DETAILS:\n"
                    f"- Order ID: #{order.id}\n"
                    f"- Customer: {order.customer_name}\n"
                    f"- Delivery Rate: ${order.rate}\n"
                    f"- Pickup Date: {pickup_date_str}\n"
                    f"- Estimated Delivery: {estimated_delivery}\n\n"
                    f"DELIVERY PARTNER INFORMATION:\n"
                    f"- Name: {driver.name}\n"
                    f"- Phone: {driver.phone_number}\n"
                    f"- Vehicle Number: {driver.vehicle_number or 'N/A'}\n\n"
                    f"PICKUP LOCATION:\n"
                    f"{order.pharmacy.name}\n"
                    f"{order.pickup_address}\n"
                    f"{order.pickup_city}\n\n"
                    f"DELIVERY LOCATION:\n"
                    f"Customer: {order.customer_name}\n"
                    f"{order.drop_address}\n"
                    f"{order.drop_city}\n\n"
                    f"Track your order through your dashboard. Questions? Contact {settings.EMAIL_ADMIN_OFFICE}\n"
                )

                _send_html_email_operations(
                    subject=f"Delivery Partner Assigned to Order #{order.id} • {settings.COMPANY_OPERATING_NAME}",
                    to_email=order.pharmacy.email,
                    html=pharmacy_html,
                    text_fallback=pharmacy_text,
                )
                print(f"SUCCESS: Pharmacy email sent to {order.pharmacy.email}")
                
            except Exception as e:
                print(f"ERROR sending pharmacy email: {str(e)}")
                import traceback
                traceback.print_exc()

            return JsonResponse({
                "message": "Driver assigned and order accepted",
                "orderId": order.id,
                "driverId": driver.id,
                "trackingId": tracking.id
            }, status=200)

        except DeliveryOrder.DoesNotExist:
            return JsonResponse({"error": "Order not found"}, status=404)
        except Driver.DoesNotExist:
            return JsonResponse({"error": "Driver not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)



@csrf_protect
@require_http_methods(["GET"])
@driver_auth_required
def get_driver_details(request):
    driver_id = request.GET.get("driverId")

    if not driver_id:
        return JsonResponse({"error": "driverId is required"}, status=400)

    try:
        driver = Driver.objects.get(id=driver_id)
        return JsonResponse({
            "id": driver.id,
            "name": driver.name,
            "phone_number": driver.phone_number,
            "vehicle_number": driver.vehicle_number,
            "active": driver.active,
            "email": driver.email,
            "identity_url": driver.identity_url
        }, status=200)

    except Driver.DoesNotExist:
        return JsonResponse({"error": "Driver not found"}, status=404)



@csrf_protect
@require_http_methods(["GET"])
@driver_auth_required
def driver_accepted_orders(request):
    """
    Returns active (accepted / picked_up / inTransit) orders
    for the authenticated driver.

    DB timestamps remain UTC.
    API response timestamps are converted to USER_TIMEZONE.
    """

    driver = request.driver  # 🔐 from JWT

    qs = (
        DeliveryOrder.objects
        .filter(
            driver=driver,
            status__in=["accepted", "picked_up", "inTransit"]
        )
        .select_related("pharmacy")
        .order_by("created_at")
    )

    orders = []

    for o in qs:
        # --------------------------------------------------
        # Distance calculation (runtime only)
        # --------------------------------------------------
        distance_km = 0
        if o.pickup_address and o.pickup_city and o.drop_address and o.drop_city:
            calculated_distance, _ = get_distance_km(
                o.pickup_address,
                o.pickup_city,
                o.drop_address,
                o.drop_city
            )
            if calculated_distance is not None:
                distance_km = round(calculated_distance, 2)

        # --------------------------------------------------
        # Store hours for pickup day (date-based)
        # --------------------------------------------------
        store_hours_for_day = None
        if o.pharmacy and o.pickup_day:
            day_key = o.pickup_day.strftime("%a")  # Mon, Tue, Wed...
            store_hours_for_day = o.pharmacy.business_hours.get(day_key)

        # --------------------------------------------------
        # ⏰ Local timezone conversion (READ ONLY)
        # --------------------------------------------------
        created_local = (
            timezone.localtime(o.created_at, settings.USER_TIMEZONE)
            if o.created_at else None
        )
        updated_local = (
            timezone.localtime(o.updated_at, settings.USER_TIMEZONE)
            if o.updated_at else None
        )

        orders.append({
            "id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "pharmacy_name": getattr(o.pharmacy, "name", None),
            "store_hours_for_pickup_day": store_hours_for_day,

            "customer_name": o.customer_name,
            "customer_phone": o.customer_phone,
            "driver_id": o.driver_id,

            "pickup_address": o.pickup_address,
            "pickup_city": o.pickup_city,
            "pickup_day": o.pickup_day.isoformat() if o.pickup_day else None,

            "drop_address": o.drop_address,
            "drop_city": o.drop_city,

            "status": o.status,
            "rate": float(o.rate) if isinstance(o.rate, Decimal) else o.rate,
            "distance_km": distance_km,

            # Delivery requirements
            "signature_required": o.signature_required,
            "id_verification_required": o.id_verification_required,
            "alternate_contact": o.alternate_contact,
            "delivery_notes": o.delivery_notes,
            "signature_ack_url": o.signature_ack_url,
            "id_verified": o.id_verified,

            # ⏰ Local time returned
            "created_at": created_local.isoformat() if created_local else None,
            "updated_at": updated_local.isoformat() if updated_local else None,
        })

    return JsonResponse({"orders": orders}, status=200)
    

@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def driver_pickup_proof(request):

    driver = request.driver      
    driver_id = driver.id
    order_id = request.POST.get("orderId")
    pharmacy_id = request.POST.get("pharmacyId")
    image_file = request.FILES.get("image")

    if not (driver_id and order_id and pharmacy_id and image_file):
        return HttpResponseBadRequest("driverId, orderId, pharmacyId and image are required")

    try:
        # Fetch objects
        order = get_object_or_404(DeliveryOrder, id=order_id)
        pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

        if order.driver_id != driver.id:
            return JsonResponse({"success": False, "error": "You are not assigned to this order"}, status=403)

        # Step 1: Upload image to GCP (OUTSIDE transaction - external service call)
        key_path = settings.GCP_KEY_PATH
        bucket_name = settings.GCP_BUCKET_NAME

        client = storage.Client.from_service_account_json(key_path)
        bucket = client.bucket(bucket_name)

        safe_pharmacy_name = pharmacy.name.replace(" ", "_")
        filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_driverpickup.jpg"
        # blob_name = f"Proof/{filename}"
        blob_name = f"{settings.GCP_PROOF_FOLDER.rstrip('/')}/{filename}"
        blob = bucket.blob(blob_name)
        blob.upload_from_file(image_file, content_type=image_file.content_type)

        # Get public URL
        public_url = f"https://storage.googleapis.com/{bucket_name}/{blob_name}"

        # Step 2: Database operations wrapped in transaction
        with transaction.atomic():
            # Update order status to inTransit
            order.status = "inTransit"
            order.save()

            # Create order tracking entry
            note_text = f"Driver Pickup Image Uploaded : {driver_id}_{order_id}_{pharmacy_id}_DriverPickup"
            performed_by = f"Driver: {driver.name}"
            OrderTracking.objects.create(
                order=order,
                driver=driver,
                pharmacy=pharmacy,
                step="inTransit",
                performed_by=performed_by,
                note=note_text,
                image_url=public_url,
            )

            # Create order image entry
            OrderImage.objects.create(
                order=order,
                image_url=public_url,
                stage="pickup"
            )

        # Step 3: Send pickup proof notification email (OUTSIDE transaction)
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            now_utc = timezone.now()
            now_local = now_utc.astimezone(settings.USER_TIMEZONE)
            now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
            logo_url = settings.LOGO_URL
            
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

            html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Picked Up • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Order #{order.id} picked up — now in transit for delivery.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Order Picked Up
                    </td>
                </tr>
                </table>
            </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Order picked up successfully! 📦
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{pharmacy.name}</strong>, your delivery order <strong>#{order.id}</strong> has been picked up 
                  by the driver and is now in transit. The driver has provided photo proof of pickup.
                </p>

                <div style="margin:18px 0;background:#eff6ff;border:1px solid #3b82f6;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#1e40af;">
                    🚚 Order Status: <strong>In Transit</strong> — On the way to customer
                  </p>
                </div>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📦 Order Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Order ID:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{order.id}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Customer:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.customer_name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivery Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        ${order.rate}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pickup Date:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pickup_date_str}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Picked Up At:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {now_str}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#fef3c7;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🚗 Driver Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Driver Name:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {driver.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Driver Phone:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {driver.phone_number}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Vehicle Number:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {driver.vehicle_number}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏢 Pharmacy Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pharmacy Name:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Phone:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.phone_number}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Address:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.store_address}, {pharmacy.city}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📸 Pickup Proof Photo
                  </p>
                  <div style="margin:12px 0;text-align:center;">
                    <img src="{public_url}" 
                         alt="Pickup Proof" 
                         style="max-width:100%;height:auto;border-radius:8px;border:2px solid #e5e7eb;">
                  </div>
                  <p style="margin:8px 0 0;font:400 12px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;text-align:center;">
                    Pickup verification photo taken by driver
                  </p>
                </div>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏠 Delivery Destination
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    Customer: {order.customer_name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_city}
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  You can track the delivery status in real-time through your dashboard. For questions, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for trusting {settings.COMPANY_OPERATING_NAME} with your deliveries!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                f"Order Picked Up - {settings.COMPANY_OPERATING_NAME}\n\n"
                f"Hello {pharmacy.name},\n\n"
                f"Your delivery order #{order.id} has been picked up by the driver and is now in transit.\n\n"
                f"ORDER INFORMATION:\n"
                f"- Order ID: #{order.id}\n"
                f"- Customer: {order.customer_name}\n"
                f"- Delivery Rate: ${order.rate}\n"
                f"- Pickup Date: {pickup_date_str}\n"
                f"- Picked Up At: {now_str}\n\n"
                f"DRIVER INFORMATION:\n"
                f"- Name: {driver.name}\n"
                f"- Phone: {driver.phone_number}\n"
                f"- Vehicle Number: {driver.vehicle_number}\n\n"
                f"PHARMACY INFORMATION:\n"
                f"- Name: {pharmacy.name}\n"
                f"- Phone: {pharmacy.phone_number}\n"
                f"- Address: {pharmacy.store_address}, {pharmacy.city}\n\n"
                f"DELIVERY DESTINATION:\n"
                f"- Customer: {order.customer_name}\n"
                f"- Address: {order.drop_address}\n"
                f"- City: {order.drop_city}\n\n"
                f"Pickup Proof Photo: {public_url}\n\n"
                f"Track your order through your dashboard.\n"
            )

            _send_html_email_operations(
                subject=f"Order #{order.id} Picked Up • In Transit",
                to_email=pharmacy.email,
                html=html,
                text_fallback=text,
            )
        except Exception as e:
            logger.error(f"ERROR sending pickup proof email: {str(e)}")
            # Don't fail the request if email fails

        return JsonResponse({
            "success": True,
            "message": "Pickup proof uploaded successfully",
            "image_url": public_url
        })

    except Exception as e:
        logger.exception("driver_pickup_proof failed")
        return JsonResponse({"success": False, "message": "Internal server error"}, status=500)


@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def driver_delivery_proof(request):

    driver = request.driver
    driver_id = driver.id
    order_id = request.POST.get("orderId")
    pharmacy_id = request.POST.get("pharmacyId")
    image_file = request.FILES.get("image")

    if not (driver_id and order_id and pharmacy_id and image_file):
        return HttpResponseBadRequest("driverId, orderId, pharmacyId and image are required")

    try:
        # Fetch objects
        order = get_object_or_404(DeliveryOrder, id=order_id)
        pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

        if order.driver_id != driver.id:
            return JsonResponse({"success": False, "error": "You are not assigned to this order"}, status=403)

        # Step 1: Upload image to GCP (OUTSIDE transaction - external service call)
        key_path = settings.GCP_KEY_PATH
        bucket_name = settings.GCP_BUCKET_NAME

        client = storage.Client.from_service_account_json(key_path)
        bucket = client.bucket(bucket_name)

        safe_pharmacy_name = pharmacy.name.replace(" ", "_")
        filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_delivered.jpg"
        # blob_name = f"Proof/{filename}"
        blob_name = f"{settings.GCP_PROOF_FOLDER.rstrip('/')}/{filename}"
        blob = bucket.blob(blob_name)
        blob.upload_from_file(image_file, content_type=image_file.content_type)

        # Get public URL
        public_url = f"https://storage.googleapis.com/{bucket_name}/{blob_name}"

        # Step 2: Database operations wrapped in transaction
        with transaction.atomic():
            # Update order status to delivered (stores in UTC)
            order.status = "delivered"
            order.is_delivered = True
            order.delivered_at = timezone.now()  # Stores in UTC
            order.save()

            # Create order tracking entry
            note_text = f"Driver Delivery Image Uploaded : {driver_id}_{order_id}_{pharmacy_id}_Delivered"
            performed_by = f"Driver: {driver.name}"
            OrderTracking.objects.create(
                order=order,
                driver=driver,
                pharmacy=pharmacy,
                step="delivered",
                performed_by=performed_by,
                note=note_text,
                image_url=public_url,
            )

            # Create order image entry
            OrderImage.objects.create(
                order=order,
                image_url=public_url,
                stage="delivered"
            )

            # Award CC Points
            try:
                # Award points to the driver
                driver_cc_account, created = CCPointsAccount.objects.get_or_create(
                    driver=driver,
                    defaults={'points_balance': 0}
                )
                driver_cc_account.points_balance += int(settings.CC_POINTS_PER_ORDER)
                driver_cc_account.save()

                # Award points to the pharmacy
                pharmacy_cc_account, created = CCPointsAccount.objects.get_or_create(
                    pharmacy=pharmacy,
                    defaults={'points_balance': 0}
                )
                pharmacy_cc_account.points_balance += int(settings.CC_POINTS_PER_ORDER)
                pharmacy_cc_account.save()

            except Exception as e:
                logger.error(f"Error awarding CC Points: {str(e)}")
                # Don't fail the transaction if CC points fail
                raise  # Re-raise to rollback the entire transaction

        # Step 3: Send delivery confirmation email (OUTSIDE transaction)
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            
            # Convert UTC time to local timezone for email display
            now_utc = timezone.now()
            now_local = now_utc.astimezone(settings.USER_TIMEZONE)
            now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
            
            logo_url = settings.LOGO_URL
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

            html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Delivered • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Order #{order.id} delivered successfully — delivery complete.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Order Delivered
                    </td>
                </tr>
                </table>
            </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Delivery completed successfully! ✅
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{pharmacy.name}</strong>, your delivery order <strong>#{order.id}</strong> has been successfully 
                  delivered to the customer. The driver has provided photo proof of delivery.
                </p>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    ✓ Order Status: <strong>Delivered</strong> — Package successfully handed to customer
                  </p>
                </div>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📦 Order Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Order ID:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{order.id}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Customer:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.customer_name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivery Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        ${order.rate}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pickup Date:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pickup_date_str}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivered At:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {now_str}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#fef3c7;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🚗 Driver Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Driver Name:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {driver.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Driver Phone:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {driver.phone_number}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Vehicle Number:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {driver.vehicle_number}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏢 Pharmacy Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pharmacy Name:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Phone:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.phone_number}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Address:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pharmacy.store_address}, {pharmacy.city}
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📸 Delivery Proof Photo
                  </p>
                  <div style="margin:12px 0;text-align:center;">
                    <img src="{public_url}" 
                         alt="Delivery Proof" 
                         style="max-width:100%;height:auto;border-radius:8px;border:2px solid #e5e7eb;">
                  </div>
                  <p style="margin:8px 0 0;font:400 12px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;text-align:center;">
                    Delivery verification photo taken by driver
                  </p>
                </div>

                <div style="margin:18px 0;background:#eff6ff;border:1px solid #3b82f6;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏠 Delivery Location
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    Customer: {order.customer_name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_city}
                  </p>
                </div>

                <div style="margin:20px 0;background:#dcfce7;border:1px solid #86efac;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    🎉 <strong>Delivery Complete!</strong> Thank you for using {settings.COMPANY_OPERATING_NAME} for your delivery needs.
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  You can view complete delivery details and proof photos in your dashboard. For questions, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for trusting {settings.COMPANY_OPERATING_NAME} with your deliveries!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                f"Order Delivered - {settings.COMPANY_OPERATING_NAME}\n\n"
                f"Hello {pharmacy.name},\n\n"
                f"Your delivery order #{order.id} has been successfully delivered to the customer.\n\n"
                f"ORDER INFORMATION:\n"
                f"- Order ID: #{order.id}\n"
                f"- Customer: {order.customer_name}\n"
                f"- Delivery Rate: ${order.rate}\n"
                f"- Pickup Date: {pickup_date_str}\n"
                f"- Delivered At: {now_str}\n\n"
                f"DRIVER INFORMATION:\n"
                f"- Name: {driver.name}\n"
                f"- Phone: {driver.phone_number}\n"
                f"- Vehicle Number: {driver.vehicle_number}\n\n"
                f"PHARMACY INFORMATION:\n"
                f"- Name: {pharmacy.name}\n"
                f"- Phone: {pharmacy.phone_number}\n"
                f"- Address: {pharmacy.store_address}, {pharmacy.city}\n\n"
                f"DELIVERY LOCATION:\n"
                f"- Customer: {order.customer_name}\n"
                f"- Address: {order.drop_address}\n"
                f"- City: {order.drop_city}\n\n"
                f"Delivery Proof Photo: {public_url}\n\n"
                f"View complete details in your dashboard.\n"
            )

            _send_html_email_operations(
                subject=f"Order #{order.id} Delivered Successfully ✓",
                to_email=pharmacy.email,
                html=html,
                text_fallback=text,
            )
        except Exception as e:
            logger.error(f"ERROR sending delivery confirmation email: {str(e)}")
            # Don't fail the request if email fails

        return JsonResponse({
            "success": True,
            "message": "Delivery proof uploaded successfully",
            "image_url": public_url
        })

    except Exception as e:
        logger.exception("driver_delivery_proof failed")
        return JsonResponse({
            "success": False,
            "message": "Internal server error"
        }, status=500)



# GCP Storage configuration
GCP_BUCKET_NAME = settings.GCP_BUCKET_NAME
GCP_FOLDER_NAME = settings.GCP_INVOICE_FOLDER


def get_gcp_storage_client():
    """Initialize and return GCP Storage client using secrets from settings"""
    try:
        credentials_dict = json.loads(settings.gcp_key_json)  # now contains JSON string from AWS Secrets
        credentials = service_account.Credentials.from_service_account_info(credentials_dict)
        client = storage.Client(credentials=credentials)
        return client
    except Exception as e:
        logger.error(f"Failed to initialize GCP storage client: {str(e)}")
        return None


def upload_pdf_to_gcp(pdf_buffer, filename):
    client = storage.Client.from_service_account_json(settings.GCP_KEY_PATH)  # same as drivers
    # bucket = client.bucket("canadrop-bucket")
    bucket = client.bucket(settings.GCP_BUCKET_NAME)
    # blob = bucket.blob(f"PharmacyInvoices/{filename}")
    blob = bucket.blob(f"{settings.GCP_INVOICE_FOLDER}/{filename}")
    pdf_buffer.seek(0)
    blob.upload_from_file(pdf_buffer, content_type="application/pdf")
    # bucket is public → public URL ok; or use signed URL if you prefer
    # return f"https://storage.googleapis.com/canadrop-bucket/PharmacyInvoices/{filename}"
    return f"https://storage.googleapis.com/{settings.GCP_BUCKET_NAME}/{settings.GCP_INVOICE_FOLDER}/{filename}"



def generate_invoice_pdf(invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount):
    """Generate comprehensive PDF invoice for pharmacy's weekly delivery summary with modern design."""
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from django.conf import settings
    from django.utils import timezone
    from datetime import datetime
    import logging
    import os
    
    logger = logging.getLogger(__name__)
    
    buffer = BytesIO()
    
    # Create PDF with professional margins
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter, 
        rightMargin=40, 
        leftMargin=40,
        topMargin=40, 
        bottomMargin=60
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # ==================== CUSTOM STYLES ====================
    
    # Modern color palette
    PRIMARY_BLUE = colors.HexColor('#0F172A')      # Deep slate
    ACCENT_BLUE = colors.HexColor('#3B82F6')       # Bright blue
    LIGHT_BG = colors.HexColor('#F8FAFC')          # Light slate
    BORDER_GRAY = colors.HexColor('#E2E8F0')       # Border gray
    TEXT_DARK = colors.HexColor('#1E293B')         # Text dark
    TEXT_GRAY = colors.HexColor('#64748B')         # Text gray
    SUCCESS_GREEN = colors.HexColor('#10B981')     # Success green
    WARNING_AMBER = colors.HexColor('#F59E0B')     # Warning amber
    
    # Invoice title - Large and bold
    invoice_title_style = ParagraphStyle(
        'InvoiceTitle',
        parent=styles['Heading1'],
        fontSize=36,
        textColor=PRIMARY_BLUE,
        fontName='Helvetica-Bold',
        alignment=TA_LEFT,
        spaceAfter=8,
        leading=42
    )
    
    # Subtitle style
    invoice_subtitle_style = ParagraphStyle(
        'InvoiceSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=TEXT_GRAY,
        fontName='Helvetica',
        alignment=TA_LEFT,
        spaceAfter=30
    )
    
    # Section headers - Modern with bottom border effect
    section_header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=PRIMARY_BLUE,
        fontName='Helvetica-Bold',
        spaceAfter=12,
        spaceBefore=25,
        leading=18
    )
    
    # Body text
    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontSize=10,
        textColor=TEXT_DARK,
        fontName='Helvetica',
        leading=14,
        spaceAfter=6
    )
    
    # Info card text
    card_text_style = ParagraphStyle(
        'CardText',
        parent=styles['Normal'],
        fontSize=10,
        textColor=TEXT_DARK,
        fontName='Helvetica',
        leading=15,
        leftIndent=0,
        rightIndent=0
    )
    
    # Footer style
    footer_style = ParagraphStyle(
        'FooterStyle',
        parent=styles['Normal'],
        fontSize=8,
        textColor=TEXT_GRAY,
        fontName='Helvetica',
        alignment=TA_CENTER,
        leading=11
    )
    
    # ==================== HEADER SECTION ====================
    
    current_date = invoice.created_at.strftime("%B %d, %Y")
    invoice_number = f"INV-{invoice.id:06d}"
    
    # Logo and company info side by side
    try:
        logo_path = settings.LOGO_PATH
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=2.2*inch, height=1.6*inch)
        else:
            raise FileNotFoundError
    except:
        # Create text-based logo if image not found
        logger.warning(f"Logo not found at path: {settings.LOGO_PATH}, using text fallback")
        logo_text = Paragraph(
            '<b><font size="20" color="#3B82F6">Cana</font><font size="20" color="#0F172A">LogistiX</font></b>',
            ParagraphStyle('LogoText', parent=styles['Normal'], alignment=TA_LEFT)
        )
        logo = logo_text
    
    company_info_text = f'''
    <b><font color="#0F172A" size="11">
        {settings.COMPANY_OPERATING_NAME}
    </font></b><br/>
    <font color="#64748B" size="9">
        {settings.COMPANY_SUB_GROUP_NAME}<br/>
        Operating Name of {settings.CORPORATION_NAME}<br/>
        BN: {settings.COMPANY_BUSINESS_NUMBER}<br/>
        {settings.EMAIL_HELP_DESK}
    </font>
    '''

    
    invoice_info_text = f'''
    <para alignment="right">
    <font color="#64748B" size="9">INVOICE NUMBER<br/></font>
    <b><font color="#0F172A" size="11">{invoice_number}</font></b><br/>
    <font color="#64748B" size="9"><br/>ISSUE DATE<br/></font>
    <b><font color="#0F172A" size="11">{current_date}</font></b>
    </para>
    '''
    
    header_data = [
        [Paragraph(company_info_text, card_text_style), Paragraph(invoice_info_text, card_text_style)]
    ]
    
    header_table = Table(header_data, colWidths=[3.5*inch, 3.5*inch])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    
    story.append(header_table)
    story.append(Spacer(1, 35))
    
    # Invoice title
    story.append(Paragraph("DELIVERY INVOICE", invoice_title_style))
    story.append(Paragraph(f"Pharmacy Delivery Services for Period {invoice.start_date.strftime('%B %d, %Y')} - {invoice.end_date.strftime('%B %d, %Y')}", invoice_subtitle_style))
    
    # Horizontal divider line
    line_table = Table([['']], colWidths=[7*inch])
    line_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 2, ACCENT_BLUE),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(line_table)
    story.append(Spacer(1, 30))
    
    # ==================== PHARMACY & INVOICE INFO CARDS ====================
    
    # Pharmacy information card
    pharmacy_card_text = f'''
    <font color="#64748B" size="8"><b>BILL TO</b></font><br/>
    <font color="#0F172A" size="11"><b>{pharmacy.name}</b></font><br/>
    <font color="#64748B" size="9">{pharmacy.store_address}<br/>
    {pharmacy.city}, {pharmacy.province} {pharmacy.postal_code}<br/>
    {pharmacy.country}<br/>
    Email: {pharmacy.email}<br/>
    Phone: {pharmacy.phone_number}</font>
    '''
    
    # Invoice details card
    due_date_formatted = invoice.due_date.strftime('%B %d, %Y')
    billing_period = f"{invoice.start_date.strftime('%B %d, %Y')} - {invoice.end_date.strftime('%B %d, %Y')}"
    
    invoice_card_text = f'''
    <font color="#64748B" size="8"><b>INVOICE DETAILS</b></font><br/>
    <font color="#0F172A" size="11"><b>Invoice #{invoice.id:06d}</b></font><br/>
    <font color="#64748B" size="9">Issue Date: {current_date}<br/>
    Due Date: <font color="#F59E0B"><b>{due_date_formatted}</b></font><br/>
    Billing Period:<br/>
    {billing_period}<br/>
    Total Deliveries: {len(orders_data)}</font>
    '''
    
    info_cards_data = [
        [Paragraph(pharmacy_card_text, card_text_style), Paragraph(invoice_card_text, card_text_style)]
    ]
    
    info_cards_table = Table(info_cards_data, colWidths=[3.5*inch, 3.5*inch])
    info_cards_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_GRAY),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 18),
        ('RIGHTPADDING', (0, 0), (-1, -1), 18),
        ('TOPPADDING', (0, 0), (-1, -1), 18),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 18),
        ('INNERGRID', (0, 0), (-1, -1), 1, BORDER_GRAY),
    ]))
    
    story.append(info_cards_table)
    story.append(Spacer(1, 35))
    
    # ==================== DELIVERY ORDERS ====================
    
    if orders_data:
        story.append(Paragraph("Delivery Orders", section_header_style))
        story.append(Spacer(1, 10))
        
        # Create order table
        order_data = [
            ['Order ID', 'Date', 'Pickup Location', 'Delivery Location', 'Amount']
        ]
        
        for order in orders_data:
            pickup_info = f"{order['pickup_address']}, {order['pickup_city']}"
            delivery_info = f"{order['drop_address']}, {order['drop_city']}"
            
            order_data.append([
                f"#{order['order_id']}",
                order['pickup_day'],
                pickup_info[:35] + '...' if len(pickup_info) > 35 else pickup_info,
                delivery_info[:35] + '...' if len(delivery_info) > 35 else delivery_info,
                f"${order['rate']:.2f}"
            ])
        
        order_table = Table(order_data, colWidths=[0.9*inch, 0.95*inch, 2.3*inch, 2.3*inch, 0.85*inch])
        order_table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Data rows
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8.5),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_DARK),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Order ID
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),  # Date
            ('ALIGN', (2, 1), (3, -1), 'LEFT'),    # Locations
            ('ALIGN', (4, 1), (4, -1), 'RIGHT'),   # Amount
            
            # Styling
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GRAY),
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, PRIMARY_BLUE),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(order_table)
        story.append(Spacer(1, 35))
    
    # ==================== INVOICE SUMMARY ====================
    
    story.append(Paragraph("Invoice Summary", section_header_style))
    
    # Summary table with modern styling
    summary_data = [
        ['', ''],
        ['Subtotal (Delivery Services)', f"${subtotal:.2f}"],
        [f'HST ({settings.ONTARIO_HST_PERCENT}%)', f"${hst_amount:.2f}"],
        ['', ''],
    ]
    
    summary_table = Table(summary_data, colWidths=[5*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (-1, -1), TEXT_DARK),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15),
        ('TOPPADDING', (0, 1), (-1, -2), 10),
        ('BOTTOMPADDING', (0, 1), (-1, -2), 10),
        ('LINEBELOW', (0, -2), (-1, -2), 1, BORDER_GRAY),
        ('BACKGROUND', (0, 1), (-1, -2), LIGHT_BG),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 5))
    
    # Total amount - Large and prominent
    total_payment_data = [
        ['TOTAL AMOUNT DUE', f"${total_amount:.2f}"]
    ]
    
    total_payment_table = Table(total_payment_data, colWidths=[5*inch, 2*inch])
    total_payment_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), ACCENT_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 16),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
    ]))
    
    story.append(total_payment_table)
    story.append(Spacer(1, 40))
    
    # ==================== PAYMENT TERMS & CONDITIONS ====================
    
    story.append(Paragraph("Payment Terms & Conditions", section_header_style))
    
    terms_text = f'''
    <b>Payment Due Date:</b> Payment is due within 2 business days of invoice issue date. The due date for this invoice is <b>{due_date_formatted}</b>.<br/><br/>
    
    <b>Service Suspension:</b> Accounts with payments overdue by more than 5 business days may be subject to temporary suspension of delivery services until all outstanding balances are settled. {settings.COMPANY_OPERATING_NAME} reserves the right to suspend service without prior notice for non-payment.<br/><br/>
    
    <b>Payment Methods</b><br/><br/>

    <b>1. Credit / Debit Card (Instant – Recommended)</b><br/>
    Payments can be made instantly through the Pharmacy Portal.<br/>
    Navigate to <b>Invoices → Select Invoice → Pay Now</b> to complete payment securely using a credit or debit card.<br/><br/>

    <b>2. Electronic Funds Transfer (EFT)</b><br/>
    Payments may be made via Electronic Funds Transfer (bank transfer).<br/>
    Please include the <b>invoice number</b> in the payment reference or memo field 
    (e.g., <b>INV-000123</b>) to ensure accurate and timely reconciliation.<br/><br/>
    Bank transfer details will be securely displayed within the Pharmacy Portal under the Invoices section.<br/><br/>

    <b>3. Company Cheque</b><br/>
    Cheques should be made payable to:<br/>
    <b>{settings.CORPORATION_NAME}</b><br/><br/>
    Please include the invoice number on the cheque memo line.<br/>
    Mailing address for cheque payments will be available in the Pharmacy Portal under the Invoices section.<br/><br/>

    <b>Important:</b> For all payment methods, referencing the invoice number ensures proper allocation of your payment.
    
    <b>Service Description:</b> This invoice covers delivery services provided during the billing period. All deliveries were completed by trained, licensed drivers following strict chain-of-custody protocols.<br/><br/>
    
    <b>Tax Information:</b> All amounts include applicable HST ({settings.ONTARIO_HST_PERCENT}%) as required by Provincial tax regulations. {settings.COMPANY_OPERATING_NAME} HST Registration Number available upon request.<br/><br/>
    
    <b>Dispute Resolution:</b>  
    Any billing disputes must be submitted <b>through the Pharmacy Portal</b> by raising a support ticket 
    <b>before the invoice due date</b>. Disputes submitted after the due date may not be considered.  
    Undisputed portions of the invoice remain payable by the stated due date.
    '''
    
    story.append(Paragraph(terms_text, body_style))
    story.append(Spacer(1, 30))
    
    # ==================== PAYMENT INSTRUCTIONS ====================
    
    story.append(Paragraph("Payment Instructions", section_header_style))
    
    payment_instructions = f'''
    <b>Method 1 - Credit / Debit Card (Instant - Recommended):</b><br/>
    Log in to your <b>Pharmacy Portal</b> and go to the <b>Invoices</b> section to pay instantly using your credit/debit card. 
    Please select the correct invoice and complete payment to receive immediate confirmation.<br/><br/>

    <b>Method 2 - Electronic Funds Transfer (EFT):</b><br/>
    Log in to your <b>Pharmacy Portal</b> and go to the <b>Invoices</b> section to view the secure EFT payment details. 
    When sending the transfer, please include the <b>Invoice Number</b> (e.g., <b>{invoice_number}</b>) in the payment reference / message field (if your bank supports it). 
    If your bank does not allow a reference, please include your <b>pharmacy name</b> and invoice number in the available notes field or notify us through the portal after sending the transfer.<br/><br/>

    <b>Method 3 - Company Cheque:</b><br/>
    Log in to your <b>Pharmacy Portal</b> and go to the <b>Invoices</b> section to confirm the current mailing address before sending a cheque. 
    Make cheques payable to <b>"{settings.CORPORATION_NAME}"</b> and include the <b>Invoice Number</b> (e.g., <b>{invoice_number}</b>) on the cheque memo line.
    '''

    
    story.append(Paragraph(payment_instructions, body_style))
    story.append(Spacer(1, 30))
    
    # ==================== QUESTIONS OR CONCERNS ====================
    
    story.append(Paragraph("Questions or Concerns?", section_header_style))
    
    support_text = f'''
    Our billing and support team is available to assist with any questions about this invoice or your delivery services. We're committed to providing exceptional service and transparent billing.<br/><br/>
    <b>Email:</b> {settings.EMAIL_HELP_DESK}<br/>
    <b>Phone:</b> Available through pharmacy portal<br/>
    <b>Support Hours:</b> Monday - Friday, 9:00 AM - 6:00 PM EST<br/>
    <b>Response Time:</b> Within 24 - 48 business hours for billing inquiries<br/><br/>
    <b>For Billing Disputes:</b> All billing disputes must be submitted by raising a support ticket through the {settings.COMPANY_OPERATING_NAME} Pharmacy Portal prior to the invoice due date. Please include the invoice number and any relevant supporting documentation when submitting your ticket.
    '''
    
    story.append(Paragraph(support_text, body_style))
    story.append(Spacer(1, 40))
    
    # ==================== FOOTER ====================
    
    footer_text = f'''
    <i>This invoice was automatically generated by {settings.COMPANY_OPERATING_NAME} billing system on {current_date}.<br/>
    Invoice Reference: {invoice_number} | Payment Due: {due_date_formatted}<br/>
    Thank you for choosing {settings.COMPANY_OPERATING_NAME} for your delivery needs!<br/>
    An Operating Name of {settings.CORPORATION_NAME}.<br/>
    © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.</i>
    '''
    
    story.append(Paragraph(footer_text, footer_style))
    
    # Build PDF
    doc.build(story)
    
    logger.info(f"Generated PDF for invoice {invoice.id}")
    return buffer



@csrf_protect
@require_http_methods(["GET"])
@pharmacy_auth_required
def generate_weekly_invoices(request):
    """
    Generate weekly invoices for authenticated pharmacy based on delivered orders.
    Returns all existing invoices AND generates new invoices for completed weeks.
    All logic is based on America/Toronto timezone.
    """
    pharmacy = request.pharmacy
    logger.info(f"Generating weekly invoices for pharmacy {pharmacy.name} (ID: {pharmacy.id})")

    # Get current datetime in USER_TIMEZONE (America/Toronto)
    now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
    today_local = now_local.date()
    
    logger.info(f"Current time: {now_local} | Today: {today_local} ({settings.USER_TIMEZONE})")

    # Fetch delivered orders with delivered_at timestamp (UTC in DB)
    orders_qs = DeliveryOrder.objects.filter(
        pharmacy=pharmacy,
        status="delivered",
        delivered_at__isnull=False
    ).order_by("delivered_at")

    if not orders_qs.exists():
        logger.info(f"No delivered orders found for pharmacy {pharmacy.name}")
        return JsonResponse({
            "success": True,
            "message": "No delivered orders for this pharmacy yet",
            "invoices": []
        })

    # Get earliest and latest delivery dates in USER_TIMEZONE
    earliest_utc = orders_qs.first().delivered_at
    latest_utc = orders_qs.last().delivered_at
    
    earliest_local = timezone.localtime(earliest_utc, settings.USER_TIMEZONE).date()
    latest_local = timezone.localtime(latest_utc, settings.USER_TIMEZONE).date()
    
    logger.info(f"Earliest delivery: {earliest_local} | Latest delivery: {latest_local}")
    logger.info(f"Total delivered orders: {orders_qs.count()}")
    
    # Start from earliest delivery date (not necessarily a Monday)
    week_start = earliest_local
    
    invoices_list = []
    weeks_processed = 0

    # Process all complete 7-day weeks
    while week_start <= latest_local:
        weeks_processed += 1
        week_end = week_start + timedelta(days=6)  # 7-day week inclusive
        
        logger.debug(f"\n--- Week #{weeks_processed}: {week_start} to {week_end} ---")
        
        # CRITICAL TIMEZONE FIX: Check if week is complete based on LOCAL timezone
        # A week is complete only when we're PAST midnight of (week_end + 1) in LOCAL timezone
        # Example: If week_end is Dec 27, week is complete when it's Dec 28 00:00:01 in Toronto
        week_end_eod_local = timezone.make_aware(
            datetime.combine(week_end, datetime.max.time()),  # 23:59:59.999999
            settings.USER_TIMEZONE
        )
        
        # Check if we've passed the end of the week in LOCAL timezone
        if now_local <= week_end_eod_local:
            logger.info(
                f"Stopping: Week {week_start} to {week_end} is incomplete. "
                f"Current time ({now_local}) is before or equal to week end ({week_end_eod_local}). "
                f"This week is still ongoing in {settings.USER_TIMEZONE}."
            )
            break
        
        logger.debug(
            f"Week is complete: current time ({now_local}) > week end ({week_end_eod_local}) "
            f"in {settings.USER_TIMEZONE}"
        )
        
        # Convert week boundaries to UTC for DB queries
        # Week starts at 00:00:00 local time
        week_start_utc = timezone.make_aware(
            datetime.combine(week_start, datetime.min.time()),
            settings.USER_TIMEZONE
        ).astimezone(timezone.utc)
        
        # Week ends at 23:59:59.999999 local time
        week_end_utc = timezone.make_aware(
            datetime.combine(week_end, datetime.max.time()),
            settings.USER_TIMEZONE
        ).astimezone(timezone.utc)

        logger.debug(
            f"UTC range for DB query: {week_start_utc} to {week_end_utc}"
        )

        # Get orders for this week (delivered_at is stored in UTC)
        week_orders = orders_qs.filter(
            delivered_at__gte=week_start_utc,
            delivered_at__lte=week_end_utc
        )
        
        total_orders = week_orders.count()
        logger.debug(f"Orders in this week: {total_orders}")

        if total_orders == 0:
            logger.debug(f"No orders in week {week_start} to {week_end}, skipping")
            week_start += timedelta(days=7)
            continue
        
        logger.info(f"Processing week {week_start} to {week_end} with {total_orders} orders")

        # Calculate amounts
        subtotal = sum(Decimal(str(o.rate)) for o in week_orders)
        hst_rate = Decimal(settings.ONTARIO_HST_RATE)
        hst_amount = (subtotal * hst_rate).quantize(Decimal('0.01'))
        total_amount_with_hst = (subtotal + hst_amount).quantize(Decimal('0.01'))

        # Due date: 2 days after today (in local timezone)
        due_date = today_local + timedelta(days=2)

        # Get or create invoice
        invoice, created = Invoice.objects.get_or_create(
            pharmacy=pharmacy,
            start_date=week_start,
            end_date=week_end,
            defaults={
                "total_orders": total_orders,
                "total_amount": total_amount_with_hst,
                "due_date": due_date,
                "status": "generated"
            }
        )

        if created:
            logger.info(f"✓ Created NEW invoice {invoice.id} for {week_start} to {week_end}")
        else:
            logger.info(f"✓ Found EXISTING invoice {invoice.id} for {week_start} to {week_end}")
            
            # Update if amounts changed
            if (invoice.total_orders != total_orders or 
                invoice.total_amount != total_amount_with_hst):
                invoice.total_orders = total_orders
                invoice.total_amount = total_amount_with_hst
                invoice.due_date = due_date
                if invoice.status is None:
                    invoice.status = "generated"
                invoice.save()
                logger.info(f"Updated invoice {invoice.id} with new totals")

        # Build orders data with LOCAL timezone timestamps
        orders_data = []
        for o in week_orders:
            delivered_at_local = timezone.localtime(o.delivered_at, settings.USER_TIMEZONE)
            orders_data.append({
                "order_id": o.id,
                "pickup_address": o.pickup_address,
                "pickup_city": o.pickup_city,
                "drop_address": o.drop_address,
                "drop_city": o.drop_city,
                "pickup_day": o.pickup_day.strftime('%Y-%m-%d'),
                "delivered_at": delivered_at_local.strftime('%Y-%m-%d %H:%M'),
                "rate": float(o.rate),
                "driver": o.driver.name if o.driver else "N/A"
            })

        # Handle PDF
        pdf_url = invoice.pdf_url or ""
        needs_upload = (
            not pdf_url
            or pdf_url.startswith("/")
            or pdf_url.startswith("/media/")
        )

        if needs_upload:
            try:
                pdf_buffer = generate_invoice_pdf(
                    invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount_with_hst
                )

                pharmacy_name_clean = (
                    pharmacy.name.replace(' ', '_')
                               .replace('/', '_')
                               .replace('\\', '_')
                )
                timestamp = now_local.strftime('%Y%m%d_%H%M%S')
                filename = (
                    f"{invoice.id}_{pharmacy_name_clean}_"
                    f"{week_start}_{week_end}_{timestamp}.pdf"
                )

                uploaded_url = upload_pdf_to_gcp(pdf_buffer, filename)
                if not uploaded_url:
                    logger.error(f"GCS upload failed for invoice {invoice.id}")
                    return JsonResponse({
                        "success": False,
                        "error": f"Failed to upload PDF for invoice {invoice.id}"
                    }, status=500)

                invoice.pdf_url = uploaded_url
                invoice.save()
                pdf_url = uploaded_url
                logger.info(f"PDF uploaded for invoice {invoice.id}")

            except Exception as e:
                logger.exception(f"PDF error for invoice {invoice.id}: {e}")
                return JsonResponse({
                    "success": False,
                    "error": f"PDF error for invoice {invoice.id}: {str(e)}"
                }, status=500)

        # Send email for new invoices
        if created and pharmacy.email:
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                logo_url = settings.LOGO_URL
                
                start_date_formatted = week_start.strftime("%B %d, %Y")
                end_date_formatted = week_end.strftime("%B %d, %Y")
                due_date_formatted = due_date.strftime("%B %d, %Y")

                company_name = settings.COMPANY_OPERATING_NAME
                company_subgroup_name = settings.COMPANY_SUB_GROUP_NAME

                invoice_html = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Invoice Generated • {company_name}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}" alt="{company_name}" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Invoice Generated
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            
            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Your weekly invoice is ready
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{pharmacy_name}</strong>, your invoice for the week of <strong>{start_date_formatted}</strong> to <strong>{end_date_formatted}</strong> has been generated.
                </p>
                
                <div style="margin:18px 0;background:#eff6ff;border:1px solid #3b82f6;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#1e40af;">
                    📄 Invoice #{invoice_id} — Payment due by <strong>{due_date_formatted}</strong>
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📊 Quick Summary
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    <strong>{total_orders} deliveries</strong> completed from {start_date_formatted} to {end_date_formatted}.
                  </p>
                  <p style="margin:8px 0 0;font:700 16px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{brand_primary};">
                    Total Amount: ${total_amount:.2f}
                  </p>
                </div>
                
                <div style="margin:18px 0;text-align:center;">
                  <a href="{pdf_url}" 
                     style="display:inline-block;background:{brand_primary};color:#ffffff;text-decoration:none;padding:12px 32px;border-radius:8px;font:600 14px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;margin-bottom:12px;">
                    📥 Download Invoice PDF
                  </a>
                </div>
                
                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;text-align:center;">
                  <p style="margin:0 0 8px;font:600 14px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📋 View Full Invoice Details
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    For a complete breakdown of charges, payment history, and delivery details, please visit the <strong>Invoices Section</strong> in your pharmacy portal.
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#fef2f2;border-left:3px solid #ef4444;border-radius:8px;padding:14px 16px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#7f1d1d;">
                    ⚠️ Payment due by <strong>{due_date_formatted}</strong> to avoid penalties or service interruptions.
                  </p>
                </div>
                
                <p style="margin:18px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Invoice generated on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
                </p>
                
                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For payment inquiries or invoice questions, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>
            
            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for choosing {company_name} for your delivery needs!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {current_year} {company_name} - {company_subgroup_name}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
""".format(
                    brand_primary=brand_primary,
                    brand_primary_dark=brand_primary_dark,
                    logo_url=logo_url,
                    pharmacy_name=pharmacy.name,
                    start_date_formatted=start_date_formatted,
                    end_date_formatted=end_date_formatted,
                    invoice_id=invoice.id,
                    due_date_formatted=due_date_formatted,
                    total_orders=total_orders,
                    total_amount=float(total_amount_with_hst),
                    pdf_url=pdf_url,
                    now_str=now_str,
                    company_name=company_name,
                    company_subgroup_name=company_subgroup_name,
                    current_year=now_local.year
                )

                invoice_text = (
                    f"Invoice Generated - {company_name}\n\n"
                    f"Hello {pharmacy.name},\n\n"
                    f"Your invoice for the week of {start_date_formatted} to {end_date_formatted} has been generated.\n\n"
                    f"Invoice #{invoice.id}\n"
                    f"Total Amount: ${total_amount_with_hst:.2f}\n"
                    f"Payment Due: {due_date_formatted}\n\n"
                    f"{total_orders} deliveries completed during this period.\n\n"
                    f"Download your invoice: {pdf_url}\n\n"
                    f"Invoice generated on {now_str}.\n"
                )

                _send_html_email_billing(
                    subject=f"Invoice #{invoice.id} Generated • Week of {start_date_formatted}",
                    to_email=pharmacy.email,
                    html=invoice_html,
                    text_fallback=invoice_text,
                )
                logger.info(f"Email sent to {pharmacy.email}")
                
            except Exception as e:
                logger.error(f"Email error: {str(e)}")

        # Add to response
        invoices_list.append({
            "invoice_id": invoice.id,
            "start_date": week_start.strftime('%Y-%m-%d'),
            "end_date": week_end.strftime('%Y-%m-%d'),
            "total_orders": invoice.total_orders,
            "subtotal": float(subtotal),
            "hst_rate": float(hst_rate),
            "hst_amount": float(hst_amount),
            "total_amount": float(invoice.total_amount),
            "due_date": invoice.due_date.strftime('%Y-%m-%d'),
            "status": invoice.status,
            "pdf_url": pdf_url,
            "created_at": timezone.localtime(
                invoice.created_at,
                settings.USER_TIMEZONE
            ).strftime('%Y-%m-%d %H:%M:%S'),
            "orders": orders_data
        })
        
        logger.debug(f"Added invoice {invoice.id} to response")

        # Move to next week
        week_start += timedelta(days=7)

    logger.info(
        f"COMPLETE: Processed {weeks_processed} weeks, "
        f"returning {len(invoices_list)} invoices: {[inv['invoice_id'] for inv in invoices_list]}"
    )
    
    return JsonResponse({
        "success": True,
        "invoices": invoices_list,
        "timezone": str(settings.USER_TIMEZONE),
        "current_date": today_local.strftime('%Y-%m-%d'),
        "current_datetime": now_local.strftime('%Y-%m-%d %H:%M:%S %Z'),
        "total_invoices": len(invoices_list)
    })

# Set Stripe API key
stripe.api_key = settings.STRIPE_SECRET_KEY

# @csrf_exempt  # CSRF exempt as requested
# @require_http_methods(["POST"])
# def create_checkout_session(request):
#     """Create Stripe checkout session for invoice payment"""
#     logger.info("=== CREATE CHECKOUT SESSION STARTED ===")
    
#     try:
#         # Log request details
#         logger.info(f"Request method: {request.method}")
#         logger.info(f"Request headers: {dict(request.headers)}")
#         logger.info(f"Request body: {request.body.decode('utf-8')}")
        
#         # Parse JSON data
#         try:
#             data = json.loads(request.body)
#             logger.info(f"Parsed data: {data}")
#         except json.JSONDecodeError as e:
#             logger.error(f"JSON decode error: {e}")
#             return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        
#         invoice_id = data.get('invoice_id')
#         pharmacy_id = data.get('pharmacy_id')
        
#         logger.info(f"Invoice ID: {invoice_id} (type: {type(invoice_id)})")
#         logger.info(f"Pharmacy ID: {pharmacy_id} (type: {type(pharmacy_id)})")
        
#         # Validate required fields
#         if not invoice_id or not pharmacy_id:
#             logger.error("Missing invoice_id or pharmacy_id")
#             return JsonResponse({'error': 'invoice_id and pharmacy_id are required'}, status=400)
        
#         # Convert to integers if they're strings
#         try:
#             invoice_id = int(invoice_id)
#             pharmacy_id = int(pharmacy_id)
#         except (ValueError, TypeError) as e:
#             logger.error(f"Error converting IDs to integers: {e}")
#             return JsonResponse({'error': 'Invalid invoice_id or pharmacy_id format'}, status=400)
        
#         # Get invoice and validate ownership
#         logger.info(f"Looking for invoice with ID: {invoice_id} and pharmacy ID: {pharmacy_id}")
#         try:
#             invoice = get_object_or_404(Invoice, id=invoice_id, pharmacy_id=pharmacy_id)
#             logger.info(f"Found invoice: {invoice}")
#             logger.info(f"Invoice status: {invoice.status}")
#             logger.info(f"Invoice total amount: {invoice.total_amount}")
#         except Exception as e:
#             logger.error(f"Error finding invoice: {e}")
#             return JsonResponse({'error': 'Invoice not found or access denied'}, status=404)
        
#         # Check if invoice is already paid
#         if invoice.status == 'paid':
#             logger.warning(f"Invoice {invoice_id} is already paid")
#             return JsonResponse({'error': 'Invoice is already paid'}, status=400)
        
#         # Get pharmacy email if available
#         pharmacy_email = None
#         try:
#             if hasattr(invoice.pharmacy, 'email') and invoice.pharmacy.email:
#                 pharmacy_email = invoice.pharmacy.email
#                 logger.info(f"Using pharmacy email: {pharmacy_email}")
#         except Exception as e:
#             logger.warning(f"Could not get pharmacy email: {e}")
        
#         # Create success and cancel URLs
#         success_url = request.build_absolute_uri('/pharmacyInvoices/') + f'?payment=success&invoice_id={invoice.id}'
#         cancel_url = request.build_absolute_uri('/pharmacyInvoices/') + '?payment=cancelled'
        
#         logger.info(f"Success URL: {success_url}")
#         logger.info(f"Cancel URL: {cancel_url}")
        
#         # Create Stripe checkout session
#         logger.info("Creating Stripe checkout session...")
#         try:
#             checkout_session_data = {
#                 'payment_method_types': ['card'],
#                 'line_items': [{
#                     'price_data': {
#                         'currency': 'cad',
#                         'product_data': {
#                             'name': f'Invoice #{str(invoice.id).zfill(6)}',
#                             'description': f'Invoice for period {invoice.start_date} to {invoice.end_date}',
#                         },
#                         'unit_amount': int(invoice.total_amount * 100),  # Convert to cents
#                     },
#                     'quantity': 1,
#                 }],
#                 'mode': 'payment',
#                 'success_url': success_url,
#                 'cancel_url': cancel_url,
#                 'metadata': {
#                     'invoice_id': str(invoice.id),
#                     'pharmacy_id': str(pharmacy_id),
#                 },
#             }
            
#             # Add customer email if available
#             if pharmacy_email:
#                 checkout_session_data['customer_email'] = pharmacy_email
            
#             logger.info(f"Checkout session data: {checkout_session_data}")
            
#             checkout_session = stripe.checkout.Session.create(**checkout_session_data)
#             logger.info(f"Stripe checkout session created: {checkout_session.id}")
#             logger.info(f"Checkout URL: {checkout_session.url}")
            
#         except stripe.error.StripeError as e:
#             logger.error(f"Stripe error: {e}")
#             return JsonResponse({'error': f'Stripe error: {str(e)}'}, status=400)
#         except Exception as e:
#             logger.error(f"Unexpected error creating Stripe session: {e}")
#             return JsonResponse({'error': f'Error creating payment session: {str(e)}'}, status=500)
        
#         response_data = {
#             'checkout_url': checkout_session.url,
#             'session_id': checkout_session.id
#         }
        
#         logger.info(f"Returning response: {response_data}")
#         logger.info("=== CREATE CHECKOUT SESSION COMPLETED SUCCESSFULLY ===")
        
#         return JsonResponse(response_data)
        
#     except Exception as e:
#         logger.error(f"Unexpected error in create_checkout_session: {e}")
#         logger.error("=== CREATE CHECKOUT SESSION FAILED ===")
#         return JsonResponse({'error': 'Internal server error'}, status=500)


@csrf_protect
@require_http_methods(["POST"])
@pharmacy_auth_required
def create_checkout_session(request):
    """Create Stripe checkout session for invoice payment"""
    logger.info("=== CREATE CHECKOUT SESSION STARTED ===")
    
    try:
        # Get pharmacy_id from the authenticated session (via decorator)
        pharmacy_id = request.COOKIES.get('pharmacyId')
        
        if not pharmacy_id:
            logger.error("Pharmacy ID not found in session")
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        # Log request details
        logger.info(f"Request method: {request.method}")
        logger.info(f"Authenticated Pharmacy ID: {pharmacy_id}")
        logger.info(f"Request body: {request.body.decode('utf-8')}")
        
        # Parse JSON data
        try:
            data = json.loads(request.body)
            logger.info(f"Parsed data: {data}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        
        invoice_id = data.get('invoice_id')
        request_pharmacy_id = data.get('pharmacy_id')
        
        logger.info(f"Invoice ID: {invoice_id} (type: {type(invoice_id)})")
        logger.info(f"Request Pharmacy ID: {request_pharmacy_id} (type: {type(request_pharmacy_id)})")
        
        # Validate required fields
        if not invoice_id:
            logger.error("Missing invoice_id")
            return JsonResponse({'error': 'invoice_id is required'}, status=400)
        
        # Convert to integers
        try:
            invoice_id = int(invoice_id)
            pharmacy_id = int(pharmacy_id)
            
            # Verify that request pharmacy_id matches authenticated pharmacy_id if provided
            if request_pharmacy_id:
                request_pharmacy_id = int(request_pharmacy_id)
                if request_pharmacy_id != pharmacy_id:
                    logger.error(f"Pharmacy ID mismatch: authenticated={pharmacy_id}, requested={request_pharmacy_id}")
                    return JsonResponse({'error': 'Access denied'}, status=403)
        except (ValueError, TypeError) as e:
            logger.error(f"Error converting IDs to integers: {e}")
            return JsonResponse({'error': 'Invalid invoice_id or pharmacy_id format'}, status=400)
        
        # Get invoice and validate ownership
        logger.info(f"Looking for invoice with ID: {invoice_id} and pharmacy ID: {pharmacy_id}")
        try:
            invoice = get_object_or_404(Invoice, id=invoice_id, pharmacy_id=pharmacy_id)
            logger.info(f"Found invoice: {invoice}")
            logger.info(f"Invoice status: {invoice.status}")
            logger.info(f"Invoice total amount: {invoice.total_amount}")
        except Exception as e:
            logger.error(f"Error finding invoice: {e}")
            return JsonResponse({'error': 'Invoice not found or access denied'}, status=404)
        
        # Check if invoice is already paid
        if invoice.status == 'paid':
            logger.warning(f"Invoice {invoice_id} is already paid")
            return JsonResponse({'error': 'Invoice is already paid'}, status=400)
        
        # Get pharmacy email if available
        pharmacy_email = None
        try:
            if hasattr(invoice.pharmacy, 'email') and invoice.pharmacy.email:
                pharmacy_email = invoice.pharmacy.email
                logger.info(f"Using pharmacy email: {pharmacy_email}")
        except Exception as e:
            logger.warning(f"Could not get pharmacy email: {e}")
        
        # Create success and cancel URLs
        success_url = request.build_absolute_uri('/pharmacyInvoices/') + f'?payment=success&invoice_id={invoice.id}'
        cancel_url = request.build_absolute_uri('/pharmacyInvoices/') + '?payment=cancelled'
        
        logger.info(f"Success URL: {success_url}")
        logger.info(f"Cancel URL: {cancel_url}")
        
        # Create Stripe checkout session
        logger.info("Creating Stripe checkout session...")
        try:
            checkout_session_data = {
                'payment_method_types': ['card'],
                'line_items': [{
                    'price_data': {
                        'currency': 'cad',
                        'product_data': {
                            'name': f'Invoice #{str(invoice.id).zfill(6)}',
                            'description': f'Invoice for period {invoice.start_date} to {invoice.end_date}',
                        },
                        'unit_amount': int(invoice.total_amount * 100),  # Convert to cents
                    },
                    'quantity': 1,
                }],
                'mode': 'payment',
                'success_url': success_url,
                'cancel_url': cancel_url,
                'metadata': {
                    'invoice_id': str(invoice.id),
                    'pharmacy_id': str(pharmacy_id),
                },
            }
            
            # Add customer email if available
            if pharmacy_email:
                checkout_session_data['customer_email'] = pharmacy_email
            
            logger.info(f"Checkout session data: {checkout_session_data}")
            
            checkout_session = stripe.checkout.Session.create(**checkout_session_data)
            logger.info(f"Stripe checkout session created: {checkout_session.id}")
            logger.info(f"Checkout URL: {checkout_session.url}")
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error: {e}")
            return JsonResponse({'error': f'Stripe error: {str(e)}'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error creating Stripe session: {e}")
            return JsonResponse({'error': f'Error creating payment session: {str(e)}'}, status=500)
        
        response_data = {
            'checkout_url': checkout_session.url,
            'session_id': checkout_session.id
        }
        
        logger.info(f"Returning response: {response_data}")
        logger.info("=== CREATE CHECKOUT SESSION COMPLETED SUCCESSFULLY ===")
        
        return JsonResponse(response_data)
        
    except Exception as e:
        logger.error(f"Unexpected error in create_checkout_session: {e}")
        logger.error("=== CREATE CHECKOUT SESSION FAILED ===")
        return JsonResponse({'error': 'Internal server error'}, status=500)



@csrf_exempt
@require_http_methods(["POST"])
def stripe_webhook(request):
    """Handle Stripe webhook events"""
    
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
    
    if not endpoint_secret:
        return HttpResponse('Webhook secret not configured', status=400)
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        return HttpResponse('Invalid payload', status=400)
    except stripe.error.SignatureVerificationError as e:
        return HttpResponse('Invalid signature', status=400)
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Get invoice details from metadata
        invoice_id = session.get('metadata', {}).get('invoice_id')
        pharmacy_id = session.get('metadata', {}).get('pharmacy_id')
        payment_intent_id = session.get('payment_intent')
        
        if invoice_id and pharmacy_id:
            try:
                # Convert to integers
                invoice_id = int(invoice_id)
                pharmacy_id = int(pharmacy_id)
                
                # Get invoice and pharmacy
                invoice = Invoice.objects.get(id=invoice_id, pharmacy_id=pharmacy_id)
                pharmacy = invoice.pharmacy
                
                # Update invoice status to paid
                invoice.status = 'paid'
                
                # Store the Stripe payment intent ID if the field exists
                if payment_intent_id:
                    if hasattr(invoice, 'stripe_payment_id'):
                        invoice.stripe_payment_id = payment_intent_id
                    elif hasattr(invoice, 'payment_id'):
                        invoice.payment_id = payment_intent_id
                
                invoice.save()
                
                # Send payment confirmation email to pharmacy
                try:
                    brand_primary = settings.BRAND_COLORS['primary']
                    brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                    brand_accent = settings.BRAND_COLORS['accent']
                    now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
                    logo_url = settings.LOGO_URL

                    html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Payment Confirmation • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
        .info-row {{ background: #1e293b !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Payment confirmed — thank you for your payment to {settings.COMPANY_OPERATING_NAME}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Payment Confirmation
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Payment Received Successfully ✓
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Thank you for your payment, <strong>{pharmacy.name}</strong>. Your invoice has been marked as paid and your account is up to date.
                </p>

                <div style="margin:20px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    <strong>✓ Payment Confirmed</strong> — Your payment has been processed successfully on <strong>{now_str}</strong>.
                  </p>
                </div>

                <h2 style="margin:24px 0 12px;font:700 18px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Invoice Details
                </h2>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Invoice Number</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">#{invoice.id}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Invoice Period</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{invoice.start_date.strftime("%b %d, %Y")} - {invoice.end_date.strftime("%b %d, %Y")}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Total Orders</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{invoice.total_orders}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Amount Paid</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:700;font-size:16px;border-top:1px solid #e2e8f0;">${invoice.total_amount}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Payment Date</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{now_str}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Payment Method</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">Stripe (Card)</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Transaction ID</td>
                      <td style="padding:12px 18px;color:#64748b;font-size:12px;border-top:1px solid #e2e8f0;">{payment_intent_id or 'N/A'}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Status</td>
                      <td style="padding:12px 18px;border-top:1px solid #e2e8f0;">
                        <span style="display:inline-block;background:#dcfce7;color:#166534;padding:4px 12px;border-radius:6px;font-weight:600;font-size:12px;">PAID</span>
                      </td>
                    </tr>
                  </table>
                </div>

                <h2 style="margin:24px 0 12px;font:700 18px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Pharmacy Information
                </h2>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Pharmacy Name</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{pharmacy.name}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.email}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.phone_number}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Address</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.store_address}, {pharmacy.city}, {pharmacy.province} {pharmacy.postal_code}</td>
                    </tr>
                  </table>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Questions about this payment? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for your continued partnership with {settings.COMPANY_OPERATING_NAME}.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                    text = (
                        f"Payment Confirmation - {settings.COMPANY_OPERATING_NAME}\n\n"
                        f"Thank you for your payment, {pharmacy.name}.\n\n"
                        "INVOICE DETAILS:\n"
                        f"Invoice Number: #{invoice.id}\n"
                        f"Invoice Period: {invoice.start_date.strftime('%b %d, %Y')} - {invoice.end_date.strftime('%b %d, %Y')}\n"
                        f"Total Orders: {invoice.total_orders}\n"
                        f"Amount Paid: ${invoice.total_amount}\n"
                        f"Payment Date: {now_str}\n"
                        f"Transaction ID: {payment_intent_id or 'N/A'}\n"
                        f"Status: PAID\n\n"
                        "PHARMACY INFORMATION:\n"
                        f"Name: {pharmacy.name}\n"
                        f"Email: {pharmacy.email}\n"
                        f"Phone: {pharmacy.phone_number}\n"
                        f"Address: {pharmacy.store_address}, {pharmacy.city}, {pharmacy.province} {pharmacy.postal_code}\n\n"
                        "Questions or need a hand? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.\n"
                    )

                    _send_html_email_admin_office(
                        subject=f"Payment Confirmation • Invoice #{invoice.id}",
                        to_email=pharmacy.email,
                        html=html,
                        text_fallback=text,
                    )
                except Exception:
                    logger.exception("Failed to send payment confirmation email")
                
            except Invoice.DoesNotExist:
                return HttpResponse('Invoice not found', status=404)
            except ValueError as e:
                return HttpResponse('Invalid metadata format', status=400)
            except Exception as e:
                return HttpResponse('Error updating invoice', status=500)
        else:
            return HttpResponse('Missing required metadata', status=400)
    
    elif event['type'] == 'payment_intent.succeeded':
        # Handle successful payment intent if needed
        payment_intent = event['data']['object']
    
    return HttpResponse(status=200)




@csrf_exempt  
def get_payment_status(request):
    """Get payment status for success page"""
    logger.info("=== GET PAYMENT STATUS ===")
    
    invoice_id = request.GET.get('invoice_id')
    payment_status = request.GET.get('payment')
    
    logger.info(f"Requested invoice ID: {invoice_id}")
    logger.info(f"Payment status: {payment_status}")
    
    if invoice_id and payment_status == 'success':
        try:
            invoice_id = int(invoice_id)
            invoice = Invoice.objects.get(id=invoice_id)
            logger.info(f"Found invoice for payment status check: {invoice}")
            
            return JsonResponse({
                'status': 'success',
                'invoice_id': invoice.id,
                'invoice_status': invoice.status,
                'message': f'Payment successful for Invoice #{str(invoice.id).zfill(6)}'
            })
        except Invoice.DoesNotExist:
            logger.error(f"Invoice {invoice_id} not found for payment status check")
            return JsonResponse({'error': 'Invoice not found'}, status=404)
        except ValueError as e:
            logger.error(f"Invalid invoice ID format: {e}")
            return JsonResponse({'error': 'Invalid invoice ID format'}, status=400)
        except Exception as e:
            logger.error(f"Error getting payment status: {e}")
            return JsonResponse({'error': 'Internal server error'}, status=500)
    
    return JsonResponse({'status': payment_status or 'unknown'})


# @csrf_protect
# @require_http_methods(["GET"])
# @pharmacy_auth_required
# def get_payment_status(request):
#     """
#     Get payment status for success page.
#     Requires pharmacy authentication and validates invoice ownership.
#     """
#     logger.info("=== GET PAYMENT STATUS STARTED ===")
    
#     try:
#         # Get authenticated pharmacy ID from session
#         pharmacy_id = request.COOKIES.get('pharmacyId')
        
#         if not pharmacy_id:
#             logger.error("Pharmacy ID not found in session")
#             return JsonResponse({
#                 'success': False,
#                 'error': 'Authentication required'
#             }, status=401)
        
#         # Convert pharmacy_id to integer
#         try:
#             pharmacy_id = int(pharmacy_id)
#             logger.info(f"Authenticated Pharmacy ID: {pharmacy_id}")
#         except (ValueError, TypeError) as e:
#             logger.error(f"Invalid pharmacy ID in session: {e}")
#             return JsonResponse({
#                 'success': False,
#                 'error': 'Invalid session data'
#             }, status=400)
        
#         # Get query parameters
#         invoice_id = request.GET.get('invoice_id')
#         payment_status = request.GET.get('payment')
        
#         logger.info(f"Requested invoice ID: {invoice_id}")
#         logger.info(f"Payment status: {payment_status}")
        
#         # Validate invoice_id is provided
#         if not invoice_id:
#             logger.warning("No invoice_id provided in request")
#             return JsonResponse({
#                 'success': False,
#                 'error': 'invoice_id parameter is required'
#             }, status=400)
        
#         # Validate payment status
#         if not payment_status:
#             logger.warning("No payment status provided in request")
#             return JsonResponse({
#                 'success': False,
#                 'error': 'payment parameter is required'
#             }, status=400)
        
#         # Convert invoice_id to integer
#         try:
#             invoice_id = int(invoice_id)
#         except (ValueError, TypeError) as e:
#             logger.error(f"Invalid invoice ID format: {invoice_id}, error: {e}")
#             return JsonResponse({
#                 'success': False,
#                 'error': 'Invalid invoice_id format'
#             }, status=400)
        
#         # Handle success payment status
#         if payment_status == 'success':
#             try:
#                 # Get invoice and validate ownership
#                 invoice = Invoice.objects.filter(
#                     id=invoice_id,
#                     pharmacy_id=pharmacy_id
#                 ).first()
                
#                 if not invoice:
#                     logger.error(
#                         f"Invoice {invoice_id} not found or access denied "
#                         f"for pharmacy {pharmacy_id}"
#                     )
#                     return JsonResponse({
#                         'success': False,
#                         'error': 'Invoice not found or access denied'
#                     }, status=404)
                
#                 logger.info(
#                     f"Found invoice {invoice.id} with status '{invoice.status}' "
#                     f"for pharmacy {pharmacy_id}"
#                 )
                
#                 # Return success response
#                 return JsonResponse({
#                     'success': True,
#                     'status': 'success',
#                     'invoice_id': invoice.id,
#                     'invoice_number': str(invoice.id).zfill(6),
#                     'invoice_status': invoice.status,
#                     'total_amount': float(invoice.total_amount),
#                     'payment_date': invoice.payment_date.isoformat() if invoice.payment_date else None,
#                     'message': f'Payment successful for Invoice #{str(invoice.id).zfill(6)}'
#                 })
                
#             except Exception as e:
#                 logger.exception(f"Unexpected error getting payment status: {e}")
#                 return JsonResponse({
#                     'success': False,
#                     'error': 'Failed to retrieve payment status'
#                 }, status=500)
        
#         # Handle cancelled or other payment statuses
#         elif payment_status == 'cancelled':
#             logger.info(f"Payment cancelled for invoice {invoice_id}")
#             return JsonResponse({
#                 'success': True,
#                 'status': 'cancelled',
#                 'invoice_id': invoice_id,
#                 'message': 'Payment was cancelled'
#             })
        
#         else:
#             logger.warning(f"Unknown payment status: {payment_status}")
#             return JsonResponse({
#                 'success': True,
#                 'status': payment_status,
#                 'invoice_id': invoice_id,
#                 'message': f'Payment status: {payment_status}'
#             })
    
#     except Exception as e:
#         logger.exception(f"Unexpected error in get_payment_status: {e}")
#         logger.error("=== GET PAYMENT STATUS FAILED ===")
#         return JsonResponse({
#             'success': False,
#             'error': 'Internal server error'
#         }, status=500)
    
#     finally:
#         logger.info("=== GET PAYMENT STATUS COMPLETED ===")




# Default user timezone (from your conversation context)
USER_TZ = settings.USER_TIMEZONE

# GCP Storage configuration
GCP_BUCKET_NAME = settings.GCP_BUCKET_NAME
GCP_FOLDER_NAME = settings.GCP_DRIVER_INVOICE_FOLDER
GCP_KEY_PATH = settings.GCP_KEY_PATH


def _start_of_week(d: date):
    """Return the Monday of the week containing date d."""
    return d - timedelta(days=d.weekday())


def _end_of_week(d: date):
    """Return the Sunday of the week containing date d."""
    return _start_of_week(d) + timedelta(days=6)


def _is_period_complete(end_date: date) -> bool:
    """
    Check if a payment period has ended (after 11:59:59 PM on end_date in local timezone).
    
    Args:
        end_date: The last date of the period (date object)
    
    Returns:
        bool: True if current local time is after end of the end_date
    """
    from datetime import datetime, time
    from django.utils import timezone
    from django.conf import settings
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Get current time in user's local timezone
    now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
    
    # Create end of day: end_date at 23:59:59.999999
    end_of_day_naive = datetime.combine(end_date, time(23, 59, 59, 999999))
    
    # Make it timezone-aware in user's local timezone
    end_of_day_local = timezone.make_aware(
        end_of_day_naive,
        settings.USER_TIMEZONE
    )
    
    # Period is complete if current local time is AFTER end of day
    is_complete = now_local > end_of_day_local
    
    # Debug logging
    logger.info(f"Period completion check:")
    logger.info(f"  End date: {end_date}")
    logger.info(f"  End of day (local): {end_of_day_local.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    logger.info(f"  Current time (local): {now_local.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    logger.info(f"  Period complete: {is_complete}")
    
    return is_complete


def _ensure_local(dt):
    """Ensure datetime is timezone-aware, then convert to USER_TZ."""
    if dt is None:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.utc)
    return dt.astimezone(USER_TZ)


def _order_to_dict(order: DeliveryOrder):
    """Serialize order fields we want to return (expand as needed)."""
    return {
        "id": order.id,
        "pharmacy_id": order.pharmacy_id,
        "driver_id": order.driver_id,
        "pickup_address": order.pickup_address,
        "pickup_city": order.pickup_city,
        "pickup_day": order.pickup_day.isoformat() if order.pickup_day else None,
        "drop_address": getattr(order, "drop_address", None) or getattr(order, "dropoff_address", None),
        "drop_city": getattr(order, "drop_city", None) or getattr(order, "dropoff_city", None),
        "status": order.status,
        "rate": str(order.rate) if order.rate is not None else "0.00",
        "created_at": _ensure_local(order.created_at).isoformat() if order.created_at else None,
        "updated_at": _ensure_local(order.updated_at).isoformat() if order.updated_at else None,
        "delivered_at": _ensure_local(order.delivered_at).isoformat() if order.delivered_at else None
    }



def _get_gcp_client():
    try:
        if not os.path.exists(GCP_KEY_PATH):
            logger.error("GCP key file not found")
            return None

        return storage.Client.from_service_account_json(GCP_KEY_PATH)
    except Exception:
        logger.exception("Failed to initialize GCP client")
        return None

def _upload_to_gcp(pdf_buffer, filename):
    """Upload PDF to GCP Storage and return the public URL."""
    try:
        if not filename:
            raise ValueError("Filename is required")

        client = _get_gcp_client()
        if not client:
            return None

        bucket = client.bucket(GCP_BUCKET_NAME)
        blob_name = f"{GCP_FOLDER_NAME}/{filename}"

        blob = bucket.blob(blob_name)
        pdf_buffer.seek(0)
        blob.upload_from_file(pdf_buffer, content_type="application/pdf")

        return f"https://storage.googleapis.com/{GCP_BUCKET_NAME}/{blob_name}"

    except Exception:
        logger.exception("Failed to upload invoice PDF to GCP")
        return None


def _generate_invoice_pdf(driver, week_data, orders):
    """
    Generate comprehensive PDF invoice for a driver's weekly payment summary with extensive details.
    
    Args:
        driver: Driver model instance
        week_data: Dictionary with keys: invoice_id, payment_period, total_orders, total_amount, due_date, status
        orders: List/QuerySet of DeliveryOrder instances
    
    Returns:
        BytesIO buffer containing the PDF
    """
    from io import BytesIO
    from decimal import Decimal
    from datetime import datetime, date
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from django.conf import settings
    from django.utils import timezone
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"=== STARTING PDF GENERATION ===")
        logger.info(f"Invoice ID: {week_data.get('invoice_id', 'MISSING!')}")
        logger.info(f"Driver: {driver.name} (ID: {driver.id})")
        logger.info(f"Orders count: {len(orders)}")
        
        # Validate invoice_id exists
        if 'invoice_id' not in week_data or week_data['invoice_id'] is None:
            raise ValueError("invoice_id is required in week_data")
        
        invoice_id = week_data['invoice_id']
        
        buffer = BytesIO()
        
        # Create PDF with professional margins (using letter size like pharmacy invoice)
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter, 
            rightMargin=40, 
            leftMargin=40,
            topMargin=40, 
            bottomMargin=60
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # ==================== CUSTOM STYLES ====================
        
        # Modern color palette
        PRIMARY_BLUE = colors.HexColor('#0F172A')      # Deep slate
        ACCENT_BLUE = colors.HexColor('#3B82F6')       # Bright blue
        LIGHT_BG = colors.HexColor('#F8FAFC')          # Light slate
        BORDER_GRAY = colors.HexColor('#E2E8F0')       # Border gray
        TEXT_DARK = colors.HexColor('#1E293B')         # Text dark
        TEXT_GRAY = colors.HexColor('#64748B')         # Text gray
        SUCCESS_GREEN = colors.HexColor('#10B981')     # Success green
        WARNING_AMBER = colors.HexColor('#F59E0B')     # Warning amber
        
        # Invoice title - Large and bold
        invoice_title_style = ParagraphStyle(
            'InvoiceTitle',
            parent=styles['Heading1'],
            fontSize=36,
            textColor=PRIMARY_BLUE,
            fontName='Helvetica-Bold',
            alignment=TA_LEFT,
            spaceAfter=8,
            leading=42
        )
        
        # Subtitle style
        invoice_subtitle_style = ParagraphStyle(
            'InvoiceSubtitle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=TEXT_GRAY,
            fontName='Helvetica',
            alignment=TA_LEFT,
            spaceAfter=30
        )
        
        # Section headers - Modern with bottom border effect
        section_header_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=PRIMARY_BLUE,
            fontName='Helvetica-Bold',
            spaceAfter=12,
            spaceBefore=25,
            leading=18
        )
        
        # Body text
        body_style = ParagraphStyle(
            'BodyText',
            parent=styles['Normal'],
            fontSize=10,
            textColor=TEXT_DARK,
            fontName='Helvetica',
            leading=14,
            spaceAfter=6
        )
        
        # Info card text
        card_text_style = ParagraphStyle(
            'CardText',
            parent=styles['Normal'],
            fontSize=10,
            textColor=TEXT_DARK,
            fontName='Helvetica',
            leading=15,
            leftIndent=0,
            rightIndent=0
        )
        
        # Footer style
        footer_style = ParagraphStyle(
            'FooterStyle',
            parent=styles['Normal'],
            fontSize=8,
            textColor=TEXT_GRAY,
            fontName='Helvetica',
            alignment=TA_CENTER,
            leading=11
        )
        
        # ==================== HEADER SECTION ====================
        
        # Format current date in local timezone
        try:
            current_date_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
            current_date = current_date_local.strftime("%B %d, %Y")
        except Exception as e:
            logger.warning(f"Error formatting date with timezone: {e}, using default")
            current_date = datetime.now().strftime("%B %d, %Y")
        
        # Format invoice number with INV- prefix (not in blue)
        invoice_number = f"INV-{invoice_id:06d}"
        logger.info(f"Formatted invoice number: {invoice_number}")
        
        # Logo and company info side by side
        try:
            logo_path = settings.LOGO_PATH
            if os.path.exists(logo_path):
                logo = Image(logo_path, width=2.2*inch, height=1.6*inch)
                logger.debug(f"Logo loaded from: {logo_path}")
            else:
                logger.warning(f"Logo file not found at: {logo_path}")
                raise FileNotFoundError("Logo file not found")
        except Exception as e:
            # Create text-based logo if image not found
            logger.warning(f"Using text-based logo due to error: {e}")
            logo_text = Paragraph(
                '<b><font size="20" color="#3B82F6">Cana</font><font size="20" color="#0F172A">LogistiX</font></b>',
                ParagraphStyle('LogoText', parent=styles['Normal'], alignment=TA_LEFT)
            )
            logo = logo_text
        
        # Company information - Extended with all business details
        company_info_text = f'''
        <b><font color="#0F172A" size="11">{settings.COMPANY_OPERATING_NAME}</font></b><br/>
        <font color="#64748B" size="9">{settings.COMPANY_SUB_GROUP_NAME}<br/>
        Operating Name of {settings.CORPORATION_NAME}<br/>
        BN: {settings.COMPANY_BUSINESS_NUMBER}<br/>
        {settings.EMAIL_HELP_DESK}
        </font>
        '''
        
        # Invoice information - Using normal formatting (not blue)
        invoice_info_text = f'''
        <para alignment="right">
        <font color="#64748B" size="9">INVOICE NUMBER<br/></font>
        <b><font color="#0F172A" size="11">{invoice_number}</font></b><br/>
        <font color="#64748B" size="9"><br/>ISSUE DATE<br/></font>
        <b><font color="#0F172A" size="11">{current_date}</font></b>
        </para>
        '''
        
        header_data = [
            [Paragraph(company_info_text, card_text_style), Paragraph(invoice_info_text, card_text_style)]
        ]
        
        header_table = Table(header_data, colWidths=[3.5*inch, 3.5*inch])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        
        story.append(header_table)
        story.append(Spacer(1, 35))
        
        # Invoice title
        story.append(Paragraph("PAYMENT INVOICE", invoice_title_style))
        
        # Format period dates
        try:
            start_date_str = week_data['payment_period']['start_date']
            end_date_str = week_data['payment_period']['end_date']
            
            logger.info(f"Parsing dates - start: {start_date_str}, end: {end_date_str}")
            
            if isinstance(start_date_str, str):
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
            else:
                start_date = start_date_str
            
            if isinstance(end_date_str, str):
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
            else:
                end_date = end_date_str
            
            start_formatted = start_date.strftime("%B %d, %Y")
            end_formatted = end_date.strftime("%B %d, %Y")
            
            logger.info(f"Formatted dates - start: {start_formatted}, end: {end_formatted}")
        except Exception as e:
            logger.error(f"Date parsing error: {e}")
            raise
        
        story.append(Paragraph(
            f"Delivery Partner Payment Services for Period {start_formatted} - {end_formatted}",
            invoice_subtitle_style
        ))
        
        # Horizontal divider line
        line_table = Table([['']], colWidths=[7*inch])
        line_table.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, -1), 2, ACCENT_BLUE),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(line_table)
        story.append(Spacer(1, 30))
        
        # ==================== DRIVER & PERIOD INFO CARDS ====================
        
        # Driver information card - Extended with all driver details
        driver_status = "Active" if getattr(driver, 'active', True) else "Inactive"
        driver_status_color = "#10B981" if getattr(driver, 'active', True) else "#EF4444"
        
        driver_vehicle = driver.vehicle_number if driver.vehicle_number else "Not Registered"
        driver_joined = driver.created_at.strftime("%B %Y") if hasattr(driver, 'created_at') else "N/A"
        
        driver_card_text = f'''
        <font color="#64748B" size="8"><b>DELIVERY PARTNER INFORMATION</b></font><br/>
        <font color="#0F172A" size="11"><b>{driver.name}</b></font><br/>
        <font color="#64748B" size="9">Email: {driver.email}<br/>
        Phone: {driver.phone_number}<br/>
        Vehicle: {driver_vehicle}<br/>
        Partner ID: #{driver.id}<br/>
        Joined: {driver_joined}<br/>
        Status: <font color="{driver_status_color}"><b>{driver_status}</b></font></font>
        '''
        
        # Payment period card with formatted dates
        try:
            due_str = week_data.get('due_date', 'N/A')
            if isinstance(due_str, str) and due_str != 'N/A':
                due_date = datetime.strptime(due_str, "%Y-%m-%d").date()
                due_formatted = due_date.strftime("%B %d, %Y")
            else:
                due_formatted = str(due_str)
        except:
            due_formatted = str(due_str)
        
        billing_period = f"{start_formatted} - {end_formatted}"
        
        period_card_text = f'''
        <font color="#64748B" size="8"><b>PAYMENT PERIOD DETAILS</b></font><br/>
        <font color="#0F172A" size="11"><b>{billing_period}</b></font><br/>
        <font color="#64748B" size="9">Invoice Number: <b>{invoice_number}</b><br/>
        Issue Date: {current_date}<br/>
        Payment Due: <font color="#F59E0B"><b>{due_formatted}</b></font><br/>
        Billing Period:<br/>
        {billing_period}<br/>
        Total Deliveries: {week_data.get('total_orders', 0)}</font>
        '''
        
        info_cards_data = [
            [Paragraph(driver_card_text, card_text_style), Paragraph(period_card_text, card_text_style)]
        ]
        
        info_cards_table = Table(info_cards_data, colWidths=[3.5*inch, 3.5*inch])
        info_cards_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_GRAY),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 18),
            ('RIGHTPADDING', (0, 0), (-1, -1), 18),
            ('TOPPADDING', (0, 0), (-1, -1), 18),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 18),
            ('INNERGRID', (0, 0), (-1, -1), 1, BORDER_GRAY),
        ]))
        
        story.append(info_cards_table)
        story.append(Spacer(1, 35))
        
        # ==================== DELIVERY ORDERS ====================
        
        if orders and len(orders) > 0:
            story.append(Paragraph("Completed Deliveries", section_header_style))
            story.append(Spacer(1, 10))
            
            # Create order table
            order_data = [
                ['Order ID', 'Date', 'Pickup Location', 'Delivery Location', 'Status', 'Rate']
            ]
            
            for order in orders:
                try:
                    # Format delivery date in local timezone
                    if order.delivered_at:
                        try:
                            delivery_date_local = timezone.localtime(order.delivered_at, settings.USER_TIMEZONE)
                            delivery_date = delivery_date_local.strftime('%m/%d/%Y')
                        except:
                            delivery_date = order.delivered_at.strftime('%m/%d/%Y')
                    else:
                        delivery_date = 'N/A'
                    
                    pickup_location = order.pickup_city if order.pickup_city else 'N/A'
                    delivery_location = getattr(order, 'drop_city', None) or getattr(order, 'dropoff_city', None) or 'N/A'
                    
                    # Safely handle rate conversion
                    rate_value = order.rate if order.rate is not None else Decimal('0.00')
                    if not isinstance(rate_value, Decimal):
                        rate_value = Decimal(str(rate_value))
                    
                    order_data.append([
                        f"#{order.id}",
                        delivery_date,
                        str(pickup_location)[:25] + '...' if len(str(pickup_location)) > 25 else str(pickup_location),
                        str(delivery_location)[:25] + '...' if len(str(delivery_location)) > 25 else str(delivery_location),
                        order.status.title() if order.status else 'N/A',
                        f"${rate_value:.2f}"
                    ])
                except Exception as e:
                    logger.warning(f"Error processing order {order.id} for PDF: {e}")
                    continue
            
            order_table = Table(order_data, colWidths=[0.8*inch, 0.95*inch, 1.8*inch, 1.8*inch, 1*inch, 0.85*inch])
            order_table.setStyle(TableStyle([
                # Header row
                ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                
                # Data rows
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8.5),
                ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_DARK),
                ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Order ID
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),  # Date
                ('ALIGN', (2, 1), (3, -1), 'LEFT'),    # Locations
                ('ALIGN', (4, 1), (4, -1), 'CENTER'),  # Status
                ('ALIGN', (5, 1), (5, -1), 'RIGHT'),   # Rate
                
                # Styling
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GRAY),
                ('LINEBELOW', (0, 0), (-1, 0), 1.5, PRIMARY_BLUE),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(order_table)
            story.append(Spacer(1, 35))
            
            logger.info(f"Added {len(order_data) - 1} orders to PDF")
        
        # ==================== FINANCIAL SUMMARY ====================
        
        story.append(Paragraph("Payment Summary", section_header_style))
        
        # Calculate financial details
        try:
            gross_amount = Decimal('0.00')
            for order in orders:
                rate = order.rate if order.rate is not None else Decimal('0.00')
                if not isinstance(rate, Decimal):
                    rate = Decimal(str(rate))
                gross_amount += rate
            
            commission_rate = Decimal(str(settings.DRIVER_COMMISSION_RATE))
            commission_percentage = int(commission_rate * 100)
            commission_amount = gross_amount * commission_rate
            net_amount = gross_amount - commission_amount
            
            logger.info(f"Financial calculations - Gross: ${gross_amount}, Commission: ${commission_amount}, Net: ${net_amount}")
        except Exception as e:
            logger.error(f"Error calculating financial details: {e}")
            raise
        
        # Summary table with modern styling
        summary_data = [
            ['', ''],
            ['Total Deliveries Completed', f"{week_data.get('total_orders', 0)} orders"],
            ['Gross Delivery Revenue', f"${gross_amount:,.2f}"],
            [f'Platform Commission ({commission_percentage}%)', f"-${commission_amount:,.2f}"],
            ['', ''],
        ]
        
        summary_table = Table(summary_data, colWidths=[5*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), TEXT_DARK),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 1), (-1, -2), 10),
            ('BOTTOMPADDING', (0, 1), (-1, -2), 10),
            ('LINEBELOW', (0, -2), (-1, -2), 1, BORDER_GRAY),
            ('BACKGROUND', (0, 1), (-1, -2), LIGHT_BG),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 5))
        
        # Net payment - Large and prominent
        net_payment_data = [
            ['NET PAYMENT DUE', f"${net_amount:,.2f}"]
        ]
        
        net_payment_table = Table(net_payment_data, colWidths=[5*inch, 2*inch])
        net_payment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), ACCENT_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 16),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))
        
        story.append(net_payment_table)
        story.append(Spacer(1, 40))
        
        # ==================== PAYMENT INFORMATION (EXTENSIVE) ====================
        
        story.append(Paragraph("Payment Information", section_header_style))
        
        payment_rate_percent = 100 - commission_percentage  # Driver receives this percentage
        
        payment_info_text = f'''
        <b>Payment Schedule:</b> Weekly payments are processed every Monday for completed deliveries from the previous week (Monday to Sunday). Payments are issued for all deliveries marked as "delivered" in the system during the billing period.<br/><br/>
        
        <b>Payment Calculation:</b> Your payment is calculated at <b>{payment_rate_percent}%</b> of the gross delivery fees. The platform retains {commission_percentage}% to cover operational costs, including customer support, insurance coverage, technology infrastructure, payment processing, and platform maintenance.<br/><br/>
        
        <b>Commission Breakdown:</b> The {commission_percentage}% platform commission covers:<br/>
        • Technology platform and mobile app maintenance<br/>
        • Customer service and support operations<br/>
        • Insurance and liability coverage<br/>
        • Payment processing and banking fees<br/>
        • Quality assurance and safety programs<br/>
        • Marketing and business development<br/><br/>
        
        <b>Payment Method:</b> Payments are transferred via direct deposit to your registered bank account within 2-3 business days of invoice processing. Please ensure your banking information is up to date in the Delivery Partner Portal. If you need to update your banking details, please submit a support ticket through the portal.<br/><br/>
        
        <b>Payment Due Date:</b> This payment is scheduled to be processed by <b>{due_formatted}</b>. You will receive a notification once the payment has been initiated. Bank processing times may vary, and funds typically appear in your account within 2-3 business days after processing.<br/><br/>
        
        <b>Payment Verification:</b> Once processed, you can verify your payment in the Delivery Partner Portal under the "Payments" section. The portal provides a complete payment history, including all invoices, payment dates, and transaction details.<br/><br/>
        
        <b>Currency:</b> All payments are made in Canadian Dollars (CAD).<br/><br/>
        
        <b>Dispute Resolution:</b> Payment disputes must be submitted within <b>7 calendar days</b> of invoice receipt. To dispute a payment, log in to the Delivery Partner Portal and raise a support ticket with the invoice number and detailed explanation. Include any supporting documentation such as delivery receipts, screenshots, or correspondence. Our support team will review your dispute and respond within 48-72 business hours.<br/><br/>
        
        <b>Disputed Amounts:</b> While disputes are being investigated, undisputed portions of payments will continue to be processed on schedule. Adjustments for validated disputes will be applied to your next scheduled payment.
        '''
        
        story.append(Paragraph(payment_info_text, body_style))
        story.append(Spacer(1, 30))
        
        # ==================== TERMS & CONDITIONS ====================
        
        story.append(Paragraph("Terms & Conditions", section_header_style))
        
        terms_text = f'''
        <b>Independent Contractor Relationship:</b> As a delivery partner with {settings.COMPANY_OPERATING_NAME}, you operate as an independent contractor, not as an employee. You are responsible for all applicable federal and provincial taxes, including income tax and GST/HST if applicable. This payment constitutes gross income for tax reporting purposes. {settings.COMPANY_OPERATING_NAME} will provide annual tax summaries, but does not withhold taxes on your behalf.<br/><br/>
        
        <b>Tax Responsibilities:</b> You are solely responsible for:<br/>
        • Filing income tax returns with the Canada Revenue Agency (CRA)<br/>
        • Paying federal and provincial income taxes<br/>
        • Registering for GST/HST if your annual revenue exceeds $30,000 CAD<br/>
        • Maintaining records of business expenses for tax deductions<br/>
        • Consulting with a tax professional regarding your obligations<br/><br/>
        
        <b>Insurance Requirements:</b> All delivery partners must maintain valid commercial vehicle insurance, commercial general liability insurance, and a valid driver's license. Proof of insurance must be submitted annually through the Delivery Partner Portal. Failure to maintain proper insurance may result in immediate suspension of delivery privileges.<br/><br/>
        
        <b>Service Standards:</b> Delivery partners are expected to maintain professional conduct, timely deliveries, and courteous customer interactions. Deliveries must follow all applicable laws and regulations, including traffic laws, privacy requirements, and product-specific handling protocols (e.g., pharmacy deliveries require chain-of-custody compliance).<br/><br/>
        
        <b>Equipment and Expenses:</b> Delivery partners are responsible for all vehicle-related expenses, including fuel, maintenance, insurance, licensing, and repairs. Partners must maintain their vehicles in safe and roadworthy condition. {settings.COMPANY_OPERATING_NAME} is not responsible for any vehicle-related costs or expenses.<br/><br/>
        
        <b>Delivery Acceptance:</b> Delivery partners have the right to accept or decline delivery requests through the platform. There is no minimum delivery requirement, and partners have full flexibility in choosing their working hours and delivery volume.<br/><br/>
        
        <b>Service Suspension or Termination:</b> {settings.COMPANY_OPERATING_NAME} reserves the right to suspend or terminate delivery partner accounts for violations of platform policies, including but not limited to: falsifying delivery records, unprofessional conduct, failure to maintain insurance, criminal activity, or repeated customer complaints. Partners will be notified of any account actions and have the right to appeal through the support ticket system.<br/><br/>
        
        <b>Payment Adjustments:</b> {settings.COMPANY_OPERATING_NAME} reserves the right to adjust payments for delivery errors, customer refunds, or chargebacks. Any adjustments will be detailed in subsequent invoices with full explanations. Partners will be notified of adjustments and may dispute them through the standard dispute resolution process.<br/><br/>
        
        <b>Platform Updates:</b> Commission rates, payment terms, and platform policies may be updated from time to time. Delivery partners will receive 30 days' advance notice of any material changes via email and portal notifications. Continued use of the platform after changes take effect constitutes acceptance of the updated terms.
        '''
        
        story.append(Paragraph(terms_text, body_style))
        story.append(Spacer(1, 30))
        
        # ==================== DATA TRACKING & PRIVACY ====================
        
        story.append(Paragraph("Data Tracking & Privacy", section_header_style))
        
        privacy_text = f'''
        <b>Delivery Tracking:</b> All deliveries are tracked via GPS and timestamped in our system for quality assurance, customer service, and payment calculation purposes. Location data is collected only during active deliveries and is used to:<br/>
        • Verify delivery completion and accuracy<br/>
        • Provide customers with real-time delivery updates<br/>
        • Calculate delivery distances and times<br/>
        • Resolve customer disputes and service issues<br/>
        • Generate payment reports and invoices<br/><br/>
        
        <b>Data Retention:</b> Delivery records, including GPS coordinates, timestamps, and delivery confirmations, are retained for a minimum of 7 years in accordance with Canadian business record retention requirements. This data may be used for financial audits, tax reporting, legal compliance, and dispute resolution.<br/><br/>
        
        <b>Privacy Compliance:</b> {settings.COMPANY_OPERATING_NAME} complies with all applicable privacy legislation, including the Personal Information Protection and Electronic Documents Act (PIPEDA). Your personal information, including name, contact details, banking information, and delivery history, is protected and will not be shared with third parties except as required for payment processing, legal compliance, or with your explicit consent.<br/><br/>
        
        <b>Data Access:</b> You have the right to access, review, and request corrections to your personal data stored in our systems. To exercise these rights, submit a support ticket through the Delivery Partner Portal specifying your request.<br/><br/>
        
        <b>Data Security:</b> We employ industry-standard security measures to protect your personal and financial information, including encryption, secure servers, and access controls. However, no system is completely secure, and you are responsible for maintaining the confidentiality of your account credentials.<br/><br/>
        
        <b>Third-Party Data Sharing:</b> Your data may be shared with authorized third parties for the following purposes only:<br/>
        • Payment processing (banking institutions)<br/>
        • Tax reporting (CRA, as required by law)<br/>
        • Insurance verification (insurance providers)<br/>
        • Legal compliance (law enforcement, regulatory bodies)<br/>
        All third-party data sharing is conducted under strict confidentiality agreements and data protection standards.
        '''
        
        story.append(Paragraph(privacy_text, body_style))
        story.append(Spacer(1, 30))
        
        # ==================== QUESTIONS OR CONCERNS ====================
        
        story.append(Paragraph("Questions or Concerns?", section_header_style))
        
        support_text = f'''
        Our delivery partner support team is available to assist with any questions about this invoice, your payments, or your delivery services. We're committed to providing exceptional support and transparent communication with all our delivery partners.<br/><br/>
        <b>Email:</b> {settings.EMAIL_HELP_DESK}<br/>
        <b>Phone:</b> Available through Delivery Partner Portal<br/>
        <b>Support Hours:</b> Monday - Friday, 9:00 AM - 6:00 PM EST<br/>
        <b>Response Time:</b> Within 24 - 48 business hours for general inquiries<br/>
        <b>Urgent Issues:</b> Payment-related urgent issues receive priority response within 12 business hours<br/><br/>
        
        <b>For Payment Inquiries:</b> All payment-related questions, including disputes, missing payments, or banking information updates, must be submitted by raising a support ticket through the {settings.COMPANY_OPERATING_NAME} Delivery Partner Portal. Please include the invoice number and any relevant supporting documentation when submitting your ticket.<br/><br/>
        
        <b>For Tax Questions:</b> While we can provide copies of payment records and annual summaries, {settings.COMPANY_OPERATING_NAME} cannot provide tax advice. Please consult with a qualified tax professional or accountant regarding your specific tax obligations and filing requirements.<br/><br/>
        
        <b>For Insurance Questions:</b> Insurance-related inquiries, including coverage requirements, policy updates, or proof of insurance submissions, can be handled through the support ticket system. Please ensure your insurance documentation is always current in the portal.<br/><br/>
        
        <b>Portal Access Issues:</b> If you experience technical difficulties accessing the Delivery Partner Portal, including login problems or system errors, please contact support immediately at {settings.EMAIL_HELP_DESK} with a detailed description of the issue.
        '''
        
        story.append(Paragraph(support_text, body_style))
        story.append(Spacer(1, 40))
        
        # ==================== FOOTER (EXTENSIVE) ====================
        
        try:
            current_year = timezone.localtime(timezone.now(), settings.USER_TIMEZONE).year
        except:
            current_year = timezone.now().year
        
        footer_text = f'''
        <i>This invoice was automatically generated by {settings.COMPANY_OPERATING_NAME} payment processing system on {current_date}.<br/>
        Invoice Reference: {invoice_number} | Payment Due: {due_formatted}<br/>
        Thank you for being a valued Delivery Partner with {settings.COMPANY_OPERATING_NAME}!<br/>
        An Operating Name of {settings.CORPORATION_NAME}.<br/>
        © {current_year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.</i>
        '''
        
        story.append(Paragraph(footer_text, footer_style))
        
        # Build PDF
        logger.info("Building PDF document...")
        doc.build(story)
        
        buffer_size = buffer.getbuffer().nbytes
        logger.info(f"=== PDF GENERATED SUCCESSFULLY === Size: {buffer_size} bytes")
        
        return buffer
        
    except Exception as e:
        logger.exception(f"CRITICAL ERROR in _generate_invoice_pdf for invoice {week_data.get('invoice_id', 'N/A')}: {e}")
        raise

@csrf_protect
@require_http_methods(["GET"])
@driver_auth_required
def driver_invoice_weeks(request):
    """
    GET endpoint: Returns weekly invoice buckets for delivered orders for authenticated driver.
    Generates PDF and uploads to GCP only after period ends (11:59 PM on end_date).
    
    - DB operations use UTC timestamps
    - API responses and PDFs use settings.USER_TIMEZONE for display
    - Requires driver authentication via @driver_auth_required decorator
    """
    logger.info("=== DRIVER INVOICE WEEKS STARTED ===")
    
    try:
        # Get authenticated driver ID from session (set by decorator)
        driver_id = request.COOKIES.get('driverId')
        
        if not driver_id:
            logger.error("Driver ID not found in session")
            return JsonResponse({
                'success': False,
                'error': 'Authentication required'
            }, status=401)
        
        # Validate and convert driver_id to integer
        try:
            driver_id = int(driver_id)
            logger.info(f"Authenticated Driver ID: {driver_id}")
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid driver ID in session: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid session data'
            }, status=400)
        
        # Validate driver exists
        try:
            driver = Driver.objects.get(pk=driver_id)
            logger.info(f"Driver found: {driver.name} (ID: {driver_id})")
        except Driver.DoesNotExist:
            logger.error(f"Driver not found with ID: {driver_id}")
            return JsonResponse({
                'success': False,
                'error': 'Driver not found'
            }, status=404)
        
        # Fetch delivered orders for this driver - IMPORTANT: Use delivered_at field
        orders_qs = DeliveryOrder.objects.filter(
            status="delivered", 
            driver_id=driver_id,
            delivered_at__isnull=False
        ).order_by("delivered_at")
        
        if not orders_qs.exists():
            logger.info(f"No delivered orders found for driver {driver_id}")
            return JsonResponse({
                'success': True,
                'message': 'No delivered orders found for this driver.',
                'driver_id': driver_id,
                'driver_name': driver.name,
                'weeks': [],
                'timezone': str(settings.USER_TIMEZONE)
            })
        
        logger.info(f"Found {orders_qs.count()} delivered orders for driver {driver_id}")
        
        # Convert UTC delivered_at to user's local timezone for grouping
        orders_with_local_dt = []
        for o in orders_qs:
            if not o.delivered_at:
                logger.warning(f"Order {o.id} has no delivered_at timestamp, skipping")
                continue
            
            # Convert UTC to local timezone
            local_dt = _ensure_local(o.delivered_at)
            orders_with_local_dt.append((o, local_dt))
            logger.debug(f"Order {o.id}: delivered_at={o.delivered_at.isoformat()} (UTC) -> {local_dt.isoformat()} (local)")
        
        if not orders_with_local_dt:
            logger.warning(f"No orders with valid delivered_at timestamps for driver {driver_id}")
            return JsonResponse({
                'success': True,
                'message': 'No orders with valid timestamps.',
                'driver_id': driver_id,
                'driver_name': driver.name,
                'weeks': [],
                'timezone': str(settings.USER_TIMEZONE)
            })
        
        # Determine overall earliest and latest based on local delivered_at
        local_datetimes = [ldt for (_, ldt) in orders_with_local_dt]
        earliest_local = min(local_datetimes)
        latest_local = max(local_datetimes)
        
        overall_start_date = _start_of_week(earliest_local.date())
        overall_end_date = _end_of_week(latest_local.date())
        
        logger.info(f"Overall period: {overall_start_date} to {overall_end_date}")
        logger.info(f"Earliest delivery (local): {earliest_local.isoformat()}")
        logger.info(f"Latest delivery (local): {latest_local.isoformat()}")
        
        # Build week buckets
        weeks = []
        cur_start = overall_start_date
        while cur_start <= overall_end_date:
            cur_end = cur_start + timedelta(days=6)
            weeks.append((cur_start, cur_end))
            cur_start = cur_start + timedelta(days=7)
        
        logger.info(f"Generated {len(weeks)} week buckets")
        
        # Prepare result weeks
        result_weeks = []
        for wstart, wend in weeks:
            # Select orders whose local delivered_at date falls inside this week
            week_orders = [
                o for (o, ldt) in orders_with_local_dt
                if (ldt.date() >= wstart and ldt.date() <= wend)
            ]
            
            if not week_orders:  # Skip weeks with no orders
                logger.debug(f"Skipping week {wstart} to {wend} - no orders")
                continue
            
            total_orders = len(week_orders)
            total_amount = Decimal("0.00")
            payment_rate_decimal = Decimal(str(1 - settings.DRIVER_COMMISSION_RATE))
            
            for o in week_orders:
                rate = o.rate if o.rate is not None else Decimal("0.00")
                if not isinstance(rate, Decimal):
                    rate = Decimal(str(rate))
                total_amount += (rate * payment_rate_decimal)
            
            due_date = wend + timedelta(days=7)
            
            logger.info(f"Processing week {wstart} to {wend}: {total_orders} orders, ${total_amount:.2f}")
            
            # Check if DriverInvoice already exists for this period
            existing_invoice = DriverInvoice.objects.filter(
                driver=driver,
                start_date=wstart,
                end_date=wend
            ).first()
            
            pdf_url = None
            invoice_status = "pending"
            invoice_created = False
            invoice_id = None
            
            # CRITICAL: Check if period is complete before generating invoice
            period_complete = _is_period_complete(wend)
            logger.info(f"Week {wstart} to {wend}: Period complete check = {period_complete}")
            
            if period_complete:
                logger.info(f"✓ Period {wstart} to {wend} is complete, processing invoice")
                
                if existing_invoice:
                    # Use existing invoice
                    pdf_url = existing_invoice.pdf_url
                    invoice_status = "generated" if pdf_url else "pending"
                    invoice_id = existing_invoice.id
                    logger.info(f"Found existing invoice ID: {invoice_id}, PDF exists: {bool(pdf_url)}")
                    
                    # If invoice exists but no PDF, regenerate it
                    if not pdf_url:
                        logger.warning(f"Invoice {invoice_id} exists but has no PDF URL. Regenerating PDF...")
                        try:
                            week_data = {
                                "invoice_id": invoice_id,
                                "payment_period": {
                                    "start_date": wstart.isoformat(),
                                    "end_date": wend.isoformat()
                                },
                                "total_orders": total_orders,
                                "total_amount": str(total_amount.quantize(Decimal("0.01"))),
                                "due_date": due_date.isoformat(),
                                "status": "generated",
                            }
                            
                            # Generate PDF
                            logger.info(f"Calling _generate_invoice_pdf for invoice {invoice_id}")
                            pdf_buffer = _generate_invoice_pdf(driver, week_data, week_orders)
                            
                            # Create filename
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            safe_driver_name = driver.name.replace(' ', '_').replace('/', '_')
                            filename = f"{driver.id}_{safe_driver_name}_{wstart.isoformat()}_{wend.isoformat()}_INV{invoice_id}_{timestamp}.pdf"
                            
                            logger.info(f"Uploading regenerated PDF to GCP: {filename}")
                            
                            # Upload to GCP
                            pdf_url = _upload_to_gcp(pdf_buffer, filename)
                            
                            if pdf_url:
                                existing_invoice.pdf_url = pdf_url
                                existing_invoice.save(update_fields=['pdf_url'])
                                invoice_status = "generated"
                                logger.info(f"✓ PDF regenerated and uploaded successfully for invoice {invoice_id}: {pdf_url}")
                            else:
                                invoice_status = "error"
                                logger.error(f"✗ Failed to upload regenerated PDF for invoice {invoice_id}")
                                
                        except Exception as e:
                            invoice_status = "error"
                            logger.exception(f"✗ CRITICAL ERROR regenerating PDF for invoice {invoice_id}: {e}")
                    
                else:
                    # Create new DriverInvoice
                    try:
                        logger.info(f"Creating new DriverInvoice for period {wstart} to {wend}")
                        new_invoice = DriverInvoice.objects.create(
                            driver=driver,
                            start_date=wstart,
                            end_date=wend,
                            total_deliveries=total_orders,
                            total_amount=total_amount.quantize(Decimal("0.01")),
                            due_date=due_date,
                            status="generated"
                        )
                        invoice_created = True
                        invoice_id = new_invoice.id
                        logger.info(f"✓ Created new invoice ID: {invoice_id}")
                        
                        # Prepare week data with invoice ID for PDF generation
                        week_data = {
                            "invoice_id": invoice_id,
                            "payment_period": {
                                "start_date": wstart.isoformat(),
                                "end_date": wend.isoformat()
                            },
                            "total_orders": total_orders,
                            "total_amount": str(total_amount.quantize(Decimal("0.01"))),
                            "due_date": due_date.isoformat(),
                            "status": "generated",
                        }
                        
                        # Generate PDF
                        try:
                            logger.info(f"Calling _generate_invoice_pdf for new invoice {invoice_id}")
                            pdf_buffer = _generate_invoice_pdf(driver, week_data, week_orders)
                            
                            # Create filename: driverId_driverName_StartDate_EndDate_InvoiceId.pdf
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            safe_driver_name = driver.name.replace(' ', '_').replace('/', '_')
                            filename = f"{driver.id}_{safe_driver_name}_{wstart.isoformat()}_{wend.isoformat()}_INV{invoice_id}_{timestamp}.pdf"
                            
                            logger.info(f"Uploading PDF to GCP: {filename}")
                            
                            # Upload to GCP
                            pdf_url = _upload_to_gcp(pdf_buffer, filename)
                            
                            if pdf_url:
                                new_invoice.pdf_url = pdf_url
                                new_invoice.save(update_fields=['pdf_url'])
                                invoice_status = "generated"
                                logger.info(f"✓ PDF uploaded successfully for invoice {invoice_id}: {pdf_url}")
                            else:
                                invoice_status = "error"
                                logger.error(f"✗ Failed to upload PDF for invoice {invoice_id}")
                                
                        except Exception as e:
                            invoice_status = "error"
                            logger.exception(f"✗ CRITICAL ERROR generating/uploading PDF for invoice {invoice_id}: {e}")
                        
                        # Send invoice notification email to delivery partner (only for new invoices with PDF)
                        if invoice_created and pdf_url and driver.email:
                            try:
                                logger.info(f"Sending invoice notification email to {driver.email} for invoice {invoice_id}")
                                
                                brand_primary = settings.BRAND_COLORS['primary']
                                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                                brand_accent = settings.BRAND_COLORS['accent']
                                
                                # Convert UTC to local timezone for email display
                                now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
                                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                                
                                logo_url = settings.LOGO_URL
                                
                                # Format dates in local timezone
                                start_date_formatted = wstart.strftime("%B %d, %Y")
                                end_date_formatted = wend.strftime("%B %d, %Y")
                                due_date_formatted = due_date.strftime("%B %d, %Y")
                                total_amount_formatted = total_amount.quantize(Decimal("0.01"))
                                payment_rate_percent = settings.PAYMENT_RATE_PERCENT
                                
                                company_name = settings.COMPANY_OPERATING_NAME
                                company_subgroup_name = settings.COMPANY_SUB_GROUP_NAME
                                
                                # Using .format() to avoid f-string CSS brace conflicts
                                driver_invoice_html = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Payment Statement Available • {company_name}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}" alt="{company_name}" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Payment Statement Ready
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            
            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Your weekly payment statement is ready
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{driver_name}</strong>, your payment statement for the week of <strong>{start_date_formatted}</strong> to <strong>{end_date_formatted}</strong> has been generated and is now available.
                </p>
                
                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #10b981;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    💰 Payment of <strong>${total_amount}</strong> will be processed by <strong>{due_date_formatted}</strong>
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📊 Payment Summary
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Invoice Number:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{invoice_number}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Statement Period:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {start_date_formatted} - {end_date_formatted}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Total Deliveries:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {total_orders} completed deliveries
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Payment Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {payment_rate_percent}% of delivery rate
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:8px 0 4px;font:700 15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;border-top:2px solid #e5e7eb;">
                        Total Payment:
                      </td>
                      <td style="padding:8px 0 4px;font:700 15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#10b981;border-top:2px solid #e5e7eb;">
                        ${total_amount}
                      </td>
                    </tr>
                  </table>
                </div>
                
                <div style="margin:18px 0;background:#fef3c7;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📅 Payment Processing
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Payment Date:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {due_date_formatted}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Payment Amount:
                      </td>
                      <td style="padding:4px 0;font:700 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                        ${total_amount}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Status:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pending Processing
                      </td>
                    </tr>
                  </table>
                </div>
                
                <div style="margin:18px 0;text-align:center;">
                  <a href="{pdf_url}" 
                     style="display:inline-block;background:{brand_primary};color:#ffffff;text-decoration:none;padding:12px 32px;border-radius:8px;font:600 14px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    📥 Download Payment Statement PDF
                  </a>
                </div>
                
                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📋 Statement Details
                  </p>
                  <p style="margin:0 0 8px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    This statement covers <strong>{total_orders} completed deliveries</strong> during the period from {start_date_formatted} to {end_date_formatted}.
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    Your payment is calculated at {payment_rate_percent}% of the total delivery rates. Download the detailed PDF statement using the button above or access it through your driver dashboard.
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#eff6ff;border-left:3px solid #3b82f6;border-radius:8px;padding:14px 16px;">
                  <p style="margin:0 0 8px;font:700 14px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#1e40af;">
                    ℹ️ Payment Information
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#1e3a8a;">
                    Your payment will be processed automatically by {due_date_formatted}. If you have any questions about this statement, please contact our operations team.
                  </p>
                </div>
                
                <p style="margin:18px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Statement generated on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
                </p>
                
                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For payment inquiries or statement questions, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>
            
            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for being a valued Delivery Partner with {company_name}!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {current_year} {company_name} - {company_subgroup_name}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
""".format(
                                    brand_primary=brand_primary,
                                    brand_primary_dark=brand_primary_dark,
                                    brand_accent=brand_accent,
                                    logo_url=logo_url,
                                    driver_name=driver.name,
                                    invoice_number=str(invoice_id).zfill(6),
                                    start_date_formatted=start_date_formatted,
                                    end_date_formatted=end_date_formatted,
                                    total_amount=total_amount_formatted,
                                    due_date_formatted=due_date_formatted,
                                    total_orders=total_orders,
                                    pdf_url=pdf_url,
                                    now_str=now_str,
                                    current_year=timezone.now().year,
                                    payment_rate_percent=payment_rate_percent,
                                    company_name=company_name,
                                    company_subgroup_name=company_subgroup_name
                                )
                                
                                driver_invoice_text = (
                                    f"Payment Statement Available - {settings.COMPANY_OPERATING_NAME}\n\n"
                                    f"Hello {driver.name},\n\n"
                                    f"Your payment statement for the week of {start_date_formatted} to {end_date_formatted} is now available.\n\n"
                                    f"PAYMENT SUMMARY:\n"
                                    f"- Invoice Number: #{str(invoice_id).zfill(6)}\n"
                                    f"- Statement Period: {start_date_formatted} - {end_date_formatted}\n"
                                    f"- Total Deliveries: {total_orders} completed deliveries\n"
                                    f"- Payment Rate: {payment_rate_percent}% of delivery rate\n"
                                    f"- Total Payment: ${total_amount_formatted}\n\n"
                                    f"PAYMENT PROCESSING:\n"
                                    f"- Payment Date: {due_date_formatted}\n"
                                    f"- Payment Amount: ${total_amount_formatted}\n"
                                    f"- Status: Pending Processing\n\n"
                                    f"Your payment will be processed automatically by {due_date_formatted}.\n\n"
                                    f"Download your statement: {pdf_url}\n\n"
                                    f"For payment inquiries, contact operations at {settings.EMAIL_OPERATIONS}\n"
                                )
                                
                                _send_html_email_billing(
                                    subject=f"Payment Statement Available • Week of {start_date_formatted} • Invoice #{str(invoice_id).zfill(6)}",
                                    to_email=driver.email,
                                    html=driver_invoice_html,
                                    text_fallback=driver_invoice_text,
                                )
                                logger.info(f"✓ Driver payment statement email sent to {driver.email} for invoice {invoice_id}")
                                
                            except Exception as e:
                                logger.exception(f"✗ ERROR sending driver invoice email to {driver.email} for invoice {invoice_id}: {str(e)}")
                                # Don't fail the invoice generation if email fails
                        
                    except Exception as e:
                        logger.exception(f"✗ Error creating invoice for week {wstart} to {wend}: {e}")
                        invoice_status = "error"
            else:
                logger.debug(f"Period {wstart} to {wend} is not complete yet, skipping invoice generation")
            
            # Serialize orders for API response
            orders_serialized = [_order_to_dict(o) for o in week_orders]
            
            # Prepare week result with invoice_id
            week_result = {
                "invoice_id": invoice_id,
                "payment_period": {
                    "start_date": wstart.isoformat(),
                    "end_date": wend.isoformat()
                },
                "total_orders": total_orders,
                "total_amount": str(total_amount.quantize(Decimal("0.01"))),
                "due_date": due_date.isoformat(),
                "status": invoice_status,
                "pdf_url": pdf_url,
                "orders": orders_serialized,
            }
            
            result_weeks.append(week_result)
            logger.info(f"Added week result for {wstart} to {wend}: invoice_id={invoice_id}, status={invoice_status}")
        
        # Prepare final response payload
        response_payload = {
            "success": True,
            "driver_id": int(driver_id),
            "driver_name": driver.name,
            "overall_period": {
                "start_date": overall_start_date.isoformat(),
                "end_date": overall_end_date.isoformat()
            },
            "total_weeks": len(result_weeks),
            "weeks": result_weeks,
            "timezone": str(settings.USER_TIMEZONE)
        }
        
        logger.info(f"=== DRIVER INVOICE WEEKS COMPLETED SUCCESSFULLY === {len(result_weeks)} weeks returned")
        
        return JsonResponse(response_payload, safe=True)
    
    except Exception as e:
        logger.exception(f"Unexpected error in driver_invoice_weeks: {e}")
        logger.error("=== DRIVER INVOICE WEEKS FAILED ===")
        return JsonResponse({
            'success': False,
            'error': 'Internal server error'
        }, status=500)



@csrf_protect
@require_http_methods(["POST"])
@user_auth_required
def contact_admin_api(request):
    try:
        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Get data
        subject = data.get('subject')
        other_subject = data.get('otherSubject', '')
        message = data.get('message')
        
        # Validate required fields
        if not subject:
            return JsonResponse({'error': 'Subject is required'}, status=400)
        
        if not message:
            return JsonResponse({'error': 'Message is required'}, status=400)
        
        # Validate 'other' subject
        if subject == 'other':
            if not other_subject or not other_subject.strip():
                return JsonResponse({'error': 'Please specify your subject when selecting "Other"'}, status=400)
            if len(other_subject) > 255:
                return JsonResponse({'error': 'Subject too long (maximum 255 characters)'}, status=400)
        
        # Validate subject choice
        valid_subjects = [
            'account_creation', 'login_problem', 'password_reset', 'profile_update',
            'order_placement', 'order_cancellation', 'order_tracking', 'order_payment',
            'pickup_issue', 'delivery_delay', 'delivery_incorrect', 'driver_unavailable',
            'invoice_generated', 'invoice_payment', 'driver_invoice',
            'technical_bug', 'cloud_storage', 'notification',
            'feedback', 'other'
        ]
        
        if subject not in valid_subjects:
            return JsonResponse({'error': 'Invalid subject category'}, status=400)
        
        # Get authenticated user from decorator
        user = request.user
        user_type_key = request.user_type
        
        # Prepare contact data
        contact_data = {
            'subject': subject,
            'message': message.strip(),
            'status': 'pending'
        }
        
        if subject == 'other':
            contact_data['other_subject'] = other_subject.strip()
        
        # Variables for email sending
        user_email = user.email
        user_name = user.name
        user_id = user.id
        user_phone = user.phone_number
        
        # Add pharmacy or driver reference based on user type
        if user_type_key == 'pharmacy':
            contact_data['pharmacy'] = user
            user_type = "Pharmacy"
        elif user_type_key == 'driver':
            contact_data['driver'] = user
            user_type = "Driver"
        else:
            return JsonResponse({'error': 'Invalid user type'}, status=400)
        
        # Create record (stored in UTC by Django)
        contact = ContactAdmin.objects.create(**contact_data)
        
        # Get current time in UTC, then convert to user timezone for display
        now_utc = timezone.now()
        user_tz = settings.USER_TIMEZONE
        now_local = now_utc.astimezone(user_tz)
        now_str = now_local.strftime("%b %d, %Y %I:%M %p %Z")
        
        # ---- Send confirmation email ----
        if user_email:
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                logo_url = settings.LOGO_URL
                
                # Format subject for display
                subject_display = subject.replace('_', ' ').title()
                if subject == 'other' and other_subject:
                    subject_display = other_subject
                
                # Truncate message for email preview (first 150 chars)
                message_preview = message.strip()
                if len(message_preview) > 150:
                    message_preview = message_preview[:150] + "..."

                html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Support Query Received • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your support query has been received — we'll get back to you soon.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Support Query Received
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {user_name or "there"}, we've received your message 
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Thank you for reaching out to <strong>{settings.COMPANY_OPERATING_NAME}</strong>. Your support query has been successfully 
                  submitted and our team will review it shortly. We typically respond within 24-48 hours.
                </p>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    Query Details:
                  </p>
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    <li><strong>Ticket ID:</strong> #{contact.id}</li>
                    <li><strong>Subject:</strong> {subject_display}</li>
                    <li><strong>User Type:</strong> {user_type}</li>
                    <li><strong>Status:</strong> Pending Review</li>
                  </ul>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border-left:3px solid {brand_accent};border-radius:8px;padding:14px 16px;">
                  <p style="margin:0 0 4px;font:600 12px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                    YOUR MESSAGE:
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    {message_preview}
                  </p>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Submitted on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Need to add more details? Just reply to this email with your ticket ID <strong>#{contact.id}</strong>.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Our support team is here to help — we'll respond as soon as possible.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_utc.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Support Query Received - {settings.COMPANY_OPERATING_NAME}\n\n"
                    f"Hi {user_name or 'there'},\n\n"
                    "Thank you for reaching out. Your support query has been successfully submitted.\n\n"
                    f"Ticket ID: #{contact.id}\n"
                    f"Subject: {subject_display}\n"
                    f"User Type: {user_type}\n"
                    f"Status: Pending Review\n\n"
                    "Our team will review your message and respond within 24-48 hours.\n\n"
                    f"Need to add more details? Reply to this email with your ticket ID #{contact.id}.\n"
                )

                _send_html_email_help_desk(
                    subject=f"Support Query Received • Ticket #{contact.id}",
                    to_email=user_email,
                    html=html,
                    text_fallback=text,
                )
            except Exception as e:
                logger.exception("Failed to send support query confirmation email")
        
        # ---- Office notification email (New Support Ticket) ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            logo_url = settings.LOGO_URL
            
            # Format subject for display
            subject_display = subject.replace('_', ' ').title()
            if subject == 'other' and other_subject:
                subject_display = other_subject
            
            # Full message for office
            message_full = message.strip()

            office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Support Ticket • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .info-row {{ background: #1e293b !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      New Support Ticket
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  New Support Ticket Raised
                </h1>
                <p style="margin:0 0 20px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  A <strong>{user_type}</strong> has raised a support ticket on the {settings.COMPANY_OPERATING_NAME} platform.
                </p>

                <div style="margin:18px 0;background:#fff7ed;border:1px solid #fb923c;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#9a3412;">
                    ⚠️ <strong>Action Required:</strong> This ticket is pending review and requires attention.
                  </p>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Ticket ID</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">#{contact.id}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">User Type</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{user_type}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">User Name</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{user_name}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{user_email}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{user_phone or 'N/A'}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">User ID</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{user_id}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Subject</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;border-top:1px solid #e2e8f0;">{subject_display}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Status</td>
                      <td style="padding:12px 18px;color:#f59e0b;font-weight:600;border-top:1px solid #e2e8f0;">PENDING</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Submitted On</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
                    </tr>
                  </table>
                </div>

                <div style="margin:20px 0;background:#f8fafc;border-left:3px solid {brand_primary};border-radius:8px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                    MESSAGE FROM USER:
                  </p>
                  <p style="margin:0;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;white-space:pre-wrap;">
{message_full}
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  This is an automated notification from the {settings.COMPANY_OPERATING_NAME} support system. Please review and respond to this ticket at your earliest convenience.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_utc.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            office_text = (
                f"New Support Ticket on {settings.COMPANY_OPERATING_NAME}\n\n"
                f"A {user_type} has raised a support ticket.\n\n"
                f"Ticket ID: #{contact.id}\n"
                f"User Type: {user_type}\n"
                f"User Name: {user_name}\n"
                f"Email: {user_email}\n"
                f"Phone: {user_phone or 'N/A'}\n"
                f"User ID: {user_id}\n"
                f"Subject: {subject_display}\n"
                f"Status: PENDING\n"
                f"Submitted On: {now_str}\n\n"
                "MESSAGE FROM USER:\n"
                f"{message_full}\n\n"
                "Please review and respond to this ticket at your earliest convenience.\n"
            )

            _send_html_email_help_desk(
                subject=f"New Support Ticket #{contact.id} from {user_type}: {subject_display}",
                to_email=settings.EMAIL_ADMIN_OFFICE,
                html=office_html,
                text_fallback=office_text,
            )
        except Exception:
            logger.exception("Failed to send office notification email for support ticket")
        
        return JsonResponse({
            'success': True,
            'message': 'Your message has been sent successfully. We will get back to you soon.',
            'contact_id': contact.id
        })
        
    except Exception as e:
        logger.exception("Error processing contact admin request")
        return JsonResponse({
            'error': 'An error occurred while processing your request. Please try again.'
        }, status=500)


OTP_TTL_SECONDS = settings.OTP_TTL_SECONDS
VERIFY_TOKEN_TTL_SECONDS = settings.VERIFY_TOKEN_TTL_SECONDS
SIGNING_SALT = settings.OTP_SIGNING_SALT

OTP_RATE_LIMIT_SECONDS = settings.OTP_RATE_LIMIT_SECONDS     
OTP_MAX_PER_HOUR = settings.OTP_MAX_PER_HOUR                  


# ---- tiny helpers ----
def _json(request: HttpRequest):
    try:
        return json.loads(request.body.decode("utf-8"))
    except Exception:
        return {}

def _ok(message, **extra):
    return JsonResponse({"success": True, "message": message, **extra})

def _err(message, code=400):
    return JsonResponse({"success": False, "message": message}, status=code)

def _otp_key(email: str) -> str:
    return f"otp:{email.strip().lower()}"

def _otp_meta_key(email: str) -> str:
    return f"otp_meta:{email.strip().lower()}"

def _rl_last_key(email: str) -> str:
    return f"otp_rl_last:{email.strip().lower()}"

def _rl_hour_key(email: str, hour_bucket: str) -> str:
    return f"otp_rl_hour:{email.strip().lower()}:{hour_bucket}"

def _valid_email(addr: str) -> bool:
    try:
        validate_email(addr)
        return True
    except ValidationError:
        return False

def _hash_otp(email: str, otp: str) -> str:
    # Store only a derived value (not plaintext OTP)
    material = f"{SIGNING_SALT}:{email.strip().lower()}:{otp}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@csrf_exempt
@require_http_methods(["POST"])
def send_otp(request: HttpRequest):
    data = _json(request)
    email = (data.get("email") or "").strip().lower()

    # Always keep responses generic to avoid user/account enumeration
    generic_ok = _ok("If a pharmacy exists for this email, an OTP will be sent shortly.")

    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")

    # ---- Rate limiting (per-email) ----
    # 1) 1 OTP per OTP_RATE_LIMIT_SECONDS
    if cache.add(_rl_last_key(email), "1", timeout=OTP_RATE_LIMIT_SECONDS) is False:
        return generic_ok

    # 2) Hard cap per hour
    hour_bucket = timezone.now().strftime("%Y%m%d%H")  # UTC bucket (safe + consistent)
    hour_key = _rl_hour_key(email, hour_bucket)
    try:
        if cache.add(hour_key, 1, timeout=3600) is False:
            count = cache.incr(hour_key)
        else:
            count = 1
    except Exception:
        # If cache backend doesn't support incr reliably, fail closed-ish but don't break UX
        count = 1

    if count > OTP_MAX_PER_HOUR:
        return generic_ok

    # Generate OTP
    otp = "".join(random.choice("0123456789") for _ in range(6))

    # Store HASHED OTP + optional metadata (not plaintext)
    otp_hash = _hash_otp(email, otp)
    cache.set(_otp_key(email), otp_hash, timeout=OTP_TTL_SECONDS)
    cache.set(_otp_meta_key(email), {"issued_at_utc": timezone.now().isoformat()}, timeout=OTP_TTL_SECONDS)

    # Timezone for email footer year (and any future displayed times)
    now_utc = timezone.now()
    try:
        user_tz = pytz.timezone(settings.USER_TIMEZONE)
        now_local = now_utc.astimezone(user_tz)
    except Exception:
        now_local = now_utc

    # --- Brand colors (bluish-green family used across the app) ---
    brand_primary = settings.BRAND_COLORS['primary']
    brand_primary_dark = settings.BRAND_COLORS['primary_dark']
    brand_accent = settings.BRAND_COLORS['accent']

    # Modern, responsive-friendly HTML (works in Gmail/Outlook/Apple Mail)
    # NOTE: Email formatting preserved; only the footer year uses USER_TIMEZONE.
    html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{settings.COMPANY_OPERATING_NAME} Verification Code</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <!-- Preheader (hidden, improves inbox preview) -->
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your {settings.COMPANY_OPERATING_NAME} verification code. Expires in {OTP_TTL_SECONDS//60} minute(s).
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <!-- Card -->
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;" class="card">
                <!-- Header bar -->
                <tr>
                <td style="background:{brand_primary};padding:18px 20px;">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                        <td align="left" style="vertical-align:middle;">
                        <img src="https://canalogistix.s3.us-east-2.amazonaws.com/Logo/CanaLogistiX_Logo_NOBG.png"
                            alt="{settings.COMPANY_OPERATING_NAME}"
                            width="64"
                            height="64"
                            style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                        </td>
                        <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,'Apple Color Emoji','Segoe UI Emoji';color:#e6fffb;">
                        Security Verification
                        </td>
                    </tr>
                    </table>
                </td>
                </tr>


            <!-- Content -->
            <tr>
              <td style="padding:28px 24px 8px 24px;">
                <h1 style="margin:0 0 10px 0;font:700 22px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Your {settings.COMPANY_OPERATING_NAME} verification code
                </h1>
                <p style="margin:0 0 18px 0;font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Use the code below to continue. For your security, don’t share it with anyone.
                </p>

                <!-- OTP box -->
                <div style="
                  margin:18px 0 10px 0;
                  background:#f0fdfa;
                  border:1px solid {brand_primary};
                  color:{brand_primary_dark};
                  border-radius:12px;
                  padding:16px 20px;
                  text-align:center;
                  font:700 28px/1.1 'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;">
                  <span style="letter-spacing:6px;display:inline-block;">{otp}</span>
                </div>

                <p style="margin:8px 0 0 0;font:500 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                  Expires in <strong>{OTP_TTL_SECONDS//60} minute(s)</strong>.
                </p>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">

                <p class="muted" style="margin:0 0 6px 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Didn’t request this? You can safely ignore this email.
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:0 24px 24px 24px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Need help? Reply to this email and our team will assist you.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <!-- Brand footer -->
          <p style="margin:14px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    subject = f"Your {settings.COMPANY_OPERATING_NAME} code • Expires in {OTP_TTL_SECONDS // 60} min"
    text = (
        f"Your {settings.COMPANY_OPERATING_NAME} verification code is: {otp}\n"
        f"This code expires in {OTP_TTL_SECONDS//60} minute(s).\n"
        "If you didn’t request it, you can ignore this message."
    )

    try:
        _send_html_email_help_desk(subject, email, html, text)
    except Exception:
        # Keep response generic (avoid account existence leak)
        logger.exception("OTP email send failed")
        return generic_ok

    return generic_ok


@csrf_exempt
@require_http_methods(["POST"])
def verify_otp(request: HttpRequest):
    data = _json(request)
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")

    if not otp.isdigit() or not (4 <= len(otp) <= 8):
        return _err("Please provide a valid OTP.")

    stored_hash = cache.get(_otp_key(email))
    if not stored_hash:
        return _err("OTP expired or not found. Please request a new one.", 400)

    # 🔐 Hash the submitted OTP exactly like send_otp
    submitted_hash = _hash_otp(email, otp)

    if not hmac.compare_digest(stored_hash, submitted_hash):
        return _err("Incorrect OTP.", 400)

    # ✅ OTP is valid — consume it (one-time use)
    cache.delete(_otp_key(email))
    cache.delete(_otp_meta_key(email))

    # Issue short-lived verification token
    token = dumps(
        {"email": email, "ts": timezone.now().timestamp()},
        salt=SIGNING_SALT
    )

    return _ok(
        "OTP verified.",
        token=token,
        expires_in=VERIFY_TOKEN_TTL_SECONDS
    )



@csrf_protect
@require_http_methods(["POST"])
def change_password(request: HttpRequest):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return _err("Invalid JSON payload", 400)

    email = (data.get("email") or "").strip().lower()
    new_password = (data.get("newPassword") or "").strip()
    confirm_password = (data.get("confirmPassword") or "").strip()
    token = (data.get("otpToken") or "").strip()

    # ---- Validation ----
    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")
    if not token:
        return _err("Missing verification token.")
    if not new_password or not confirm_password:
        return _err("Please provide both password fields.")
    if new_password != confirm_password:
        return _err("New Password and Confirm Password must match.")
    
    # ---- Enhanced Password Validation ----
    if len(new_password) < 8:
        return _err("Password must be at least 8 characters long.")
    
    if not re.search(r'[A-Z]', new_password):
        return _err("Password must include at least one uppercase letter.")
    
    if not re.search(r'[a-z]', new_password):
        return _err("Password must include at least one lowercase letter.")
    
    if not re.search(r'[0-9]', new_password):
        return _err("Password must include at least one number.")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return _err("Password must include at least one special character (!@#$%^&*).")

    # ---- Verify OTP token ----
    try:
        token_data = loads(
            token,
            salt=SIGNING_SALT,
            max_age=VERIFY_TOKEN_TTL_SECONDS
        )
    except (SignatureExpired, BadSignature):
        return _err("Verification token is invalid or expired.", 400)

    if token_data.get("email") != email:
        return _err("Verification token does not match this email.", 400)

    # ---- Fetch pharmacy ----
    try:
        pharmacy = Pharmacy.objects.get(email__iexact=email)
    except Pharmacy.DoesNotExist:
        return _err("No pharmacy account found with this email.", 404)

    # ---- DB WRITE (UTC) ----
    pharmacy.password = make_password(new_password)
    pharmacy.save(update_fields=["password"])

    # ---- Time handling ----
    changed_at_utc = timezone.now()  # DB truth (UTC)
    try:
        changed_at_local = changed_at_utc.astimezone(USER_TZ)
    except Exception:
        changed_at_local = changed_at_utc

    changed_at = changed_at_local.strftime("%b %d, %Y %H:%M %Z")

    # ---- Email (HTML UNCHANGED) ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']

        logo_url = settings.LOGO_URL
        site_url = settings.SITE_URL.rstrip("/")
        reset_link = f"{site_url}/forgotPassword/" if site_url else "/forgotPassword/"

        html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed Successfully • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
        .panel {{ background:#0b1220 !important; border-color:#1f2937 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your {settings.COMPANY_OPERATING_NAME} password was changed on {changed_at}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;" class="card">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%">
                  <tr>
                    <td>
                      <img src="{logo_url}" width="64" height="64" style="border-radius:50%;">
                    </td>
                    <td align="right" style="color:#e6fffb;font-weight:600;">
                      Security Notification
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 10px 24px;">
                <h1>Password Changed Successfully</h1>
                <p>
                  Your {settings.COMPANY_OPERATING_NAME} account password was changed on
                  <strong style="color:{brand_primary_dark}">{changed_at}</strong>.
                </p>

                <table width="100%" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:14px 16px;">
                      <p>If <strong>you</strong> made this change, no further action is needed.</p>
                      <p>If this wasn't you, please reset your password immediately</p>
                    </td>
                  </tr>
                </table>

                <p class="muted" style="margin-top:16px;">
                  For your security, never share your password with anyone.
                </p>
              </td>
            </tr>
          </table>

          <p style="margin-top:14px;font-size:12px;color:#94a3b8;">
            © {changed_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

        text = (
            f"{settings.COMPANY_OPERATING_NAME} — Password Changed Successfully\n\n"
            f"Timestamp: {changed_at}\n\n"
            "If you did not make this change, please reset your password immediately:\n"
            f"{reset_link}\n"
        )

        _send_html_email_help_desk(
            subject=f"Your {settings.COMPANY_OPERATING_NAME} password was changed",
            to_email=email,
            html=html,
            text_fallback=text,
        )

    except Exception:
        logger.exception("Password-change email failed")

    return _ok(
        "Password changed successfully.",
        changed_at=changed_at
    )


# @csrf_exempt
# def change_password_driver(request: HttpRequest):
#     if request.method != "POST":
#         return _err("Method not allowed", 405)

#     data = _json(request)
#     email = (data.get("email") or "").strip().lower()
#     new_password = (data.get("newPassword") or "").strip()
#     confirm_password = (data.get("confirmPassword") or "").strip()
#     token = (data.get("otpToken") or "").strip()

#     if not email or not _valid_email(email):
#         return _err("Please provide a valid email address.")
#     if not token:
#         return _err("Missing verification token.")
#     if not new_password or not confirm_password:
#         return _err("Please provide both password fields.")
#     if new_password != confirm_password:
#         return _err("New Password and Confirm Password must match.")
#     if len(new_password) < 8:
#         return _err("Password must be at least 8 characters long.")

#     try:
#         token_data = loads(token, salt=SIGNING_SALT, max_age=VERIFY_TOKEN_TTL_SECONDS)
#     except SignatureExpired:
#         return _err("Verification token is invalid or expired.", 400)
#     except BadSignature:
#         return _err("Verification token is invalid or expired.", 400)

#     if token_data.get("email") != email:
#         return _err("Verification token does not match this email.", 400)

#     # Update DRIVER password
#     try:
#         driver = Driver.objects.get(email__iexact=email)
#     except Driver.DoesNotExist:
#         return _err("No driver account found with this email.", 404)

#     driver.password = make_password(new_password)
#     driver.save(update_fields=["password"])

#     # ---- Dark theme email (bluish grey + teal accent) ----
#     try:
#         brand_primary = settings.BRAND_COLORS['primary']
#         brand_primary_dark = settings.BRAND_COLORS['primary_dark']
#         bg_dark = settings.BRAND_COLORS['bg_dark']
#         card_dark = settings.BRAND_COLORS['card_dark']
#         border_dark = settings.BRAND_COLORS['border_dark']
#         text_light = settings.BRAND_COLORS['text_light']
#         text_muted = settings.BRAND_COLORS['text_muted']

#         logo_url = settings.LOGO_URL
#         changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")

#         html = f"""
# <!doctype html>
# <html lang="en">
#   <head>
#     <meta charset="utf-8">
#     <title>Password Changed • {settings.COMPANY_OPERATING_NAME} Driver</title>
#     <meta name="viewport" content="width=device-width, initial-scale=1">
#   </head>
#   <body style="margin:0;padding:0;background:{bg_dark};">
#     <!-- Preheader (hidden) -->
#     <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
#       Your {settings.COMPANY_OPERATING_NAME} driver password was changed on {changed_at}.
#     </div>

#     <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};padding:24px 12px;">
#       <tr>
#         <td align="center">
#           <!-- Card -->
#           <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:{card_dark};border:1px solid {border_dark};border-radius:16px;overflow:hidden;">
#             <!-- Header bar -->
#             <tr>
#             <td style="background:{brand_primary};padding:18px 20px;">
#                 <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
#                 <tr>
#                     <td align="left" style="vertical-align:middle;">
#                     <img src="{logo_url}"
#                         alt="{settings.COMPANY_OPERATING_NAME}"
#                         width="64"
#                         height="64"
#                         style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
#                     </td>
#                     <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
#                     Security Notification
#                     </td>
#                 </tr>
#                 </table>
#             </td>
#             </tr>


#             <!-- Content -->
#             <tr>
#               <td style="padding:28px 24px 10px 24px;">
#                 <h1 style="margin:0 0 10px 0;font:700 22px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
#                   Password Changed Successfully
#                 </h1>
#                 <p style="margin:0 0 16px 0;font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
#                   Your {settings.COMPANY_OPERATING_NAME} <strong style="color:{text_light};">driver</strong> account password was changed on
#                   <strong style="color:{brand_primary};">{changed_at}</strong>.
#                 </p>

#                 <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;">
#                   <tr>
#                     <td style="padding:14px 16px;">
#                       <p style="margin:0 0 6px 0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
#                         If <strong>you</strong> made this change, no further action is needed.
#                       </p>
#                       <p style="margin:0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
#                         If this wasn’t you, please reset your password immediately.
#                       </p>
#                     </td>
#                   </tr>
#                 </table>

#                 <p style="margin:16px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
#                   For your security, never share your password with anyone.
#                 </p>
#               </td>
#             </tr>

#             <!-- Footer -->
#             <tr>
#               <td style="padding:0 24px 24px 24px;">
#                 <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;">
#                   <tr>
#                     <td style="padding:12px 16px;">
#                       <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
#                         Need help? Reply to this email and our team will assist you.
#                       </p>
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>

#           </table>

#           <!-- Brand footer -->
#           <p style="margin:14px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
#             © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
#           </p>
#         </td>
#       </tr>
#     </table>
#   </body>
# </html>
# """
#         text = (
#             f"{settings.COMPANY_OPERATING_NAME} — Driver Password Changed Successfully\n\n"
#             f"Timestamp: {changed_at}\n\n"
#             "If you did not make this change, please reset your password immediately."
#         )

#         _send_html_email_help_desk(
#             subject=f"Your {settings.COMPANY_OPERATING_NAME} driver password was changed",
#             to_email=email,
#             html=html,
#             text_fallback=text,
#         )
#     except Exception:
#         logger.exception("Driver password-change email failed to send")

#     return _ok("Driver password changed successfully.")


import re

@csrf_protect
@require_http_methods(["POST"])
def change_password_driver(request: HttpRequest):
    # ---- Parse JSON safely ----
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return _err("Invalid JSON payload", 400)

    email = (data.get("email") or "").strip().lower()
    new_password = (data.get("newPassword") or "").strip()
    confirm_password = (data.get("confirmPassword") or "").strip()
    token = (data.get("otpToken") or "").strip()

    # ---- Validation ----
    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")
    if not token:
        return _err("Missing verification token.")
    if not new_password or not confirm_password:
        return _err("Please provide both password fields.")
    if new_password != confirm_password:
        return _err("New Password and Confirm Password must match.")
    
    # ---- Enhanced Password Validation ----
    if len(new_password) < 8:
        return _err("Password must be at least 8 characters long.")
    
    if not re.search(r'[A-Z]', new_password):
        return _err("Password must include at least one uppercase letter.")
    
    if not re.search(r'[a-z]', new_password):
        return _err("Password must include at least one lowercase letter.")
    
    if not re.search(r'[0-9]', new_password):
        return _err("Password must include at least one number.")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return _err("Password must include at least one special character (!@#$%^&*).")

    # ---- Verify OTP token (email-bound, time-bound) ----
    try:
        token_data = loads(
            token,
            salt=SIGNING_SALT,
            max_age=VERIFY_TOKEN_TTL_SECONDS
        )
    except (SignatureExpired, BadSignature):
        return _err("Verification token is invalid or expired.", 400)

    if token_data.get("email") != email:
        return _err("Verification token does not match this email.", 400)

    # ---- Fetch driver ----
    try:
        driver = Driver.objects.get(email__iexact=email)
    except Driver.DoesNotExist:
        return _err("No driver account found with this email.", 404)

    # ---- DB WRITE (UTC truth) ----
    driver.password = make_password(new_password)
    driver.save(update_fields=["password"])

    # ---- Time handling ----
    changed_at_utc = timezone.now()  # DB truth (UTC)
    try:
        changed_at_local = changed_at_utc.astimezone(USER_TZ)
    except Exception:
        changed_at_local = changed_at_utc

    changed_at = changed_at_local.strftime("%b %d, %Y %H:%M %Z")

    # ---- Email (HTML preserved, only time injected) ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        bg_dark = settings.BRAND_COLORS['bg_dark']
        card_dark = settings.BRAND_COLORS['card_dark']
        border_dark = settings.BRAND_COLORS['border_dark']
        text_light = settings.BRAND_COLORS['text_light']
        text_muted = settings.BRAND_COLORS['text_muted']

        logo_url = settings.LOGO_URL

        html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed • {settings.COMPANY_OPERATING_NAME} Driver</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background:{bg_dark};">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your {settings.COMPANY_OPERATING_NAME} driver password was changed on {changed_at}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
            style="max-width:560px;background:{card_dark};border:1px solid {border_dark};border-radius:16px;overflow:hidden;">

            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%">
                  <tr>
                    <td>
                      <img src="{logo_url}" width="64" height="64" style="border-radius:50%;">
                    </td>
                    <td align="right" style="color:#e6fffb;font-weight:600;">
                      Security Notification
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 10px 24px;">
                <h1 style="color:{text_light};">Password Changed Successfully</h1>
                <p style="color:{text_muted};">
                  Your {settings.COMPANY_OPERATING_NAME} <strong>driver</strong> account password
                  was changed on <strong style="color:{brand_primary};">{changed_at}</strong>.
                </p>

                <table width="100%" style="background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;">
                  <tr>
                    <td style="padding:14px 16px;">
                      <p style="color:{text_light};">If <strong>you</strong> made this change, no action is needed.</p>
                      <p style="color:{text_muted};">If this wasn't you, reset your password immediately.</p>
                    </td>
                  </tr>
                </table>

                <p style="margin-top:16px;color:{text_muted};font-size:12px;">
                  For your security, never share your password with anyone.
                </p>
              </td>
            </tr>
          </table>

          <p style="margin-top:14px;font-size:12px;color:{text_muted};">
            © {changed_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

        text = (
            f"{settings.COMPANY_OPERATING_NAME} — Driver Password Changed Successfully\n\n"
            f"Timestamp: {changed_at}\n\n"
            "If you did not make this change, please reset your password immediately."
        )

        _send_html_email_help_desk(
            subject=f"Your {settings.COMPANY_OPERATING_NAME} driver password was changed",
            to_email=email,
            html=html,
            text_fallback=text,
        )

    except Exception:
        logger.exception("Driver password-change email failed")

    return _ok(
        "Driver password changed successfully.",
        changed_at=changed_at
    )

import re
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.db import transaction, IntegrityError
from django.utils import timezone
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import logging

logger = logging.getLogger(__name__)

# Assuming these are defined in your settings or constants
# SIGNING_SALT = "your-signing-salt"
# VERIFY_TOKEN_TTL_SECONDS = 600
# USER_TZ = pytz.timezone("America/Toronto")


@csrf_protect
@require_http_methods(["POST"])
def register_pharmacy(request: HttpRequest):
    """
    POST /api/auth/register-pharmacy/
    JSON body:
    {
      "name": "Acme Pharmacy",
      "store_address": "123 Main St",
      "city": "Toronto",
      "province": "ON",
      "postal_code": "M5V 2T6",
      "country": "Canada",
      "phone_number": "416-555-1212",
      "email": "owner@example.com",
      "password": "StrongPass#1",
      "otpToken": "<token returned by /api/auth/verify-otp/>"
    }
    
    Returns:
    {
      "success": true,
      "message": "Registration successful.",
      "id": 123,
      "email": "owner@example.com",
      "registered_at": "Jan 03, 2026 14:30 EST"
    }
    """
    # ---- Parse JSON safely ----
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return _err("Invalid JSON payload", 400)

    # ---- Extract and normalize fields ----
    name          = (data.get("name") or "").strip()
    store_address = (data.get("store_address") or "").strip()
    city          = (data.get("city") or "").strip()
    province      = (data.get("province") or "").strip()
    postal_code   = (data.get("postal_code") or "").strip()
    country       = (data.get("country") or "").strip()
    phone_number  = (data.get("phone_number") or "").strip()
    email         = (data.get("email") or "").strip().lower()
    password      = (data.get("password") or "").strip()
    otp_token     = (data.get("otpToken") or "").strip()

    # ---- Validation ----
    required_fields = {
        "name": name,
        "store_address": store_address,
        "city": city,
        "province": province,
        "postal_code": postal_code,
        "country": country,
        "phone_number": phone_number,
        "email": email,
        "password": password,
        "otpToken": otp_token,
    }
    missing = [k for k, v in required_fields.items() if not v]
    if missing:
        return _err("Missing required fields.", 400, missing=missing)

    if not _valid_email(email):
        return _err("Please provide a valid email address.")

    # ---- Enhanced Password Validation ----
    if len(password) < 8:
        return _err("Password must be at least 8 characters long.")
    
    if not re.search(r'[A-Z]', password):
        return _err("Password must include at least one uppercase letter.")
    
    if not re.search(r'[a-z]', password):
        return _err("Password must include at least one lowercase letter.")
    
    if not re.search(r'[0-9]', password):
        return _err("Password must include at least one number.")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return _err("Password must include at least one special character (!@#$%^&*).")

    # ---- Verify OTP token ----
    try:
        token_data = loads(
            otp_token, 
            salt=SIGNING_SALT, 
            max_age=VERIFY_TOKEN_TTL_SECONDS
        )
    except (SignatureExpired, BadSignature):
        return _err("Verification token is invalid or expired.", 400)

    token_email = (token_data.get("email") or "").strip().lower()
    if token_email != email:
        return _err("Verification token does not match this email.", 400)

    # ---- Create pharmacy (UTC timestamp in DB) ----
    try:
        with transaction.atomic():
            pharmacy = Pharmacy.objects.create(
                name=name,
                store_address=store_address,
                city=city,
                province=province,
                postal_code=postal_code,
                country=country,
                phone_number=phone_number,
                email=email,
                password=password,  # Hashed by Pharmacy.save() or override
            )
    except IntegrityError:
        return _err("An account with this email already exists.", 409)

    # ---- Time handling (DB=UTC, Display=Local) ----
    registered_at_utc = timezone.now()  # DB truth (UTC)
    try:
        registered_at_local = registered_at_utc.astimezone(USER_TZ)
    except Exception:
        registered_at_local = registered_at_utc
    
    registered_at = registered_at_local.strftime("%b %d, %Y %H:%M %Z")

    # ---- Send welcome email to pharmacy ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        brand_accent = settings.BRAND_COLORS['accent']
        logo_url = settings.LOGO_URL

        html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to {settings.COMPANY_OPERATING_NAME} • Pharmacy Registration</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Registration confirmed — welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Welcome to {settings.COMPANY_OPERATING_NAME}
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {name or "there"}, your pharmacy is all set 🎉
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Thanks for registering with <strong>{settings.COMPANY_OPERATING_NAME}</strong> an operating name of {settings.CORPORATION_NAME} and joining the <strong>Cana Family by {settings.COMPANY_SUB_GROUP_NAME}</strong>.
                  We're excited to help your team coordinate secure, trackable, and timely deliveries with a dashboard
                  designed for pharmacies.
                </p>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    <li>Live order tracking with photo proof at each stage</li>
                    <li>Professional Delivery Management System using Customer ID and Signature Verifications
                    <li>Smart weekly invoices and transparent earnings</li>
                    <li>Secure driver handover and delivery confirmations</li>
                  </ul>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Registered on <strong style="color:{brand_primary_dark};">{registered_at}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Questions or need a hand? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Welcome aboard — we're thrilled to partner with you.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {registered_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            f"Welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}!\n\n"
            f"Hi {name or 'there'}, your pharmacy registration is confirmed.\n"
            "• Live order tracking with photo proof\n"
            "• Weekly invoices and transparent earnings\n"
            "• Secure handover and delivery confirmations\n\n"
            "Questions? Just reply to this email.\n"
        )

        _send_html_email_help_desk(
            subject=f"Welcome to {settings.COMPANY_OPERATING_NAME} • Pharmacy Registration Confirmed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send pharmacy registration email")
    
    # ---- Send office notification email ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        logo_url = settings.LOGO_URL

        office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Pharmacy Registration • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .info-row {{ background: #1e293b !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      New Pharmacy Registered
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  New Pharmacy Registration
                </h1>
                <p style="margin:0 0 20px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  A new pharmacy has successfully registered on the {settings.COMPANY_OPERATING_NAME} platform.
                </p>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Pharmacy Name</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{name}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{email}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{phone_number}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Address</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{store_address}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">City</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{city}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Province</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{province}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Postal Code</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{postal_code}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Country</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{country}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Registration Time</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{registered_at}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Pharmacy ID</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.id}</td>
                    </tr>
                  </table>
                </div>

                <div style="margin:20px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    <strong>✓ Registration Complete</strong> — The pharmacy has been added to the system and received their welcome email.
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  This is an automated notification from the {settings.COMPANY_OPERATING_NAME} registration system.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {registered_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        office_text = (
            f"New Pharmacy Registration on {settings.COMPANY_OPERATING_NAME}\n\n"
            f"Pharmacy Name: {name}\n"
            f"Email: {email}\n"
            f"Phone: {phone_number}\n"
            f"Address: {store_address}\n"
            f"City: {city}\n"
            f"Province: {province}\n"
            f"Postal Code: {postal_code}\n"
            f"Country: {country}\n"
            f"Registration Time: {registered_at}\n"
            f"Pharmacy ID: {pharmacy.id}\n\n"
            "The pharmacy has been added to the system and received their welcome email.\n"
        )

        _send_html_email_help_desk(
            subject=f"New Pharmacy Registration: {name}",
            to_email=settings.EMAIL_ADMIN_OFFICE,
            html=office_html,
            text_fallback=office_text,
        )
    except Exception:
        logger.exception("Failed to send office notification email for pharmacy registration")

    return _ok(
        "Registration successful.",
        id=pharmacy.id,
        email=pharmacy.email,
        registered_at=registered_at
    )



@csrf_protect
@require_http_methods(["POST"])
def register_driver(request: HttpRequest):
    """
    POST /api/driver/register/
    JSON body:
    {
      "name": "John Doe",
      "phone_number": "416-555-1212",
      "email": "driver@example.com",
      "password": "StrongPass#1",
      "vehicle_number": "ABC-1234",
      "otpToken": "<token from /api/auth/verify-otp/>"
    }
    
    Returns:
    {
      "success": true,
      "message": "Driver registration successful.",
      "id": 456,
      "email": "driver@example.com",
      "registered_at": "Jan 03, 2026 14:30 EST"
    }
    """
    # ---- Parse JSON safely ----
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return _err("Invalid JSON payload", 400)

    # ---- Extract and normalize fields ----
    name           = (data.get("name") or "").strip()
    phone_number   = (data.get("phone_number") or "").strip()
    email          = (data.get("email") or "").strip().lower()
    password       = (data.get("password") or "").strip()
    vehicle_number = (data.get("vehicle_number") or "").strip()
    otp_token      = (data.get("otpToken") or "").strip()

    # ---- Validation ----
    required_fields = {
        "name": name,
        "phone_number": phone_number,
        "email": email,
        "password": password,
        "vehicle_number": vehicle_number,
        "otpToken": otp_token,
    }
    missing = [k for k, v in required_fields.items() if not v]
    if missing:
        return _err("Missing required fields.", 400, missing=missing)

    if not _valid_email(email):
        return _err("Please provide a valid email address.")

    # ---- Enhanced Password Validation ----
    if len(password) < 8:
        return _err("Password must be at least 8 characters long.")
    
    if not re.search(r'[A-Z]', password):
        return _err("Password must include at least one uppercase letter.")
    
    if not re.search(r'[a-z]', password):
        return _err("Password must include at least one lowercase letter.")
    
    if not re.search(r'[0-9]', password):
        return _err("Password must include at least one number.")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return _err("Password must include at least one special character (!@#$%^&*).")

    # ---- Verify OTP token ----
    try:
        token_data = loads(
            otp_token,
            salt=SIGNING_SALT,
            max_age=VERIFY_TOKEN_TTL_SECONDS
        )
    except (SignatureExpired, BadSignature):
        return _err("Verification token is invalid or expired.", 400)

    token_email = (token_data.get("email") or "").strip().lower()
    if token_email != email:
        return _err("Verification token does not match this email.", 400)

    # ---- Create Driver (UTC timestamp in DB) ----
    try:
        with transaction.atomic():
            driver = Driver.objects.create(
                name=name,
                phone_number=phone_number,
                email=email,
                password=password,  # Hashed by Driver.save() or override
                vehicle_number=vehicle_number,
            )
    except IntegrityError:
        return _err("An account with this email already exists.", 409)

    # ---- Time handling (DB=UTC, Display=Local) ----
    registered_at_utc = timezone.now()  # DB truth (UTC)
    try:
        registered_at_local = registered_at_utc.astimezone(USER_TZ)
    except Exception:
        registered_at_local = registered_at_utc
    
    registered_at = registered_at_local.strftime("%b %d, %Y %H:%M %Z")

    # ---- Send welcome email to driver ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        bg_dark = settings.BRAND_COLORS['bg_dark']
        card_dark = settings.BRAND_COLORS['card_dark']
        border_dark = settings.BRAND_COLORS['border_dark']
        text_light = settings.BRAND_COLORS['text_light']
        text_muted = settings.BRAND_COLORS['text_muted']
        logo_url = settings.LOGO_URL

        html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to {settings.COMPANY_OPERATING_NAME} • Driver Registration</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background:{bg_dark};">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Registration confirmed — welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:640px;background:{card_dark};border:1px solid {border_dark};border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Welcome to {settings.COMPANY_OPERATING_NAME}
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
                  Hey {name or "driver"}, you're in!
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Welcome to <strong style="color:{text_light};">{settings.COMPANY_OPERATING_NAME}</strong> an operating name of <strong style="color:{text_light};">{settings.CORPORATION_NAME}</strong> and the <strong style="color:{text_light};">Cana Family by {settings.COMPANY_SUB_GROUP_NAME}</strong>.
                  You now have access to a streamlined delivery experience with clear routes, photo-verified steps, and
                  weekly earnings summaries.
                </p>

                <div style="margin:18px 0;background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;padding:16px 18px;">
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
                    <li>Pickup → in-transit → delivered — all verified with photos</li>
                    <li>Clear delivery details and navigation shortcuts</li>
                    <li>Secure Customer ID and Signature Verifications.
                    <li>Automatic bi-weekly payouts with transparent summaries</li>
                  </ul>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Registered on <strong style="color:{text_light};">{registered_at}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid {border_dark};margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Drive safe and welcome aboard. Need help? Reply to this email and our team will assist you.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
            © {registered_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            f"Welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}!\n\n"
            f"Hey {name or 'driver'}, your driver registration is confirmed.\n"
            "• Photo-verified delivery steps\n"
            "• Clear delivery details and navigation\n"
            "• Weekly earnings summaries\n\n"
            "Questions or need a hand? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.\n"
        )

        _send_html_email_help_desk(
            subject=f"Welcome to {settings.COMPANY_OPERATING_NAME} • Delivery Partner Registration Confirmed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send driver registration email")
    
    # ---- Send office notification email ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        logo_url = settings.LOGO_URL

        office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Delivery Partner Registration • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .info-row {{ background: #1e293b !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      New Delivery Partner Registered
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  New Delivery Partner Registration
                </h1>
                <p style="margin:0 0 20px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  A new delivery partner has successfully registered on the {settings.COMPANY_OPERATING_NAME} platform.
                </p>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Driver Name</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{name}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{email}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{phone_number}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Vehicle Number</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{vehicle_number}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Registration Time</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{registered_at}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Driver ID</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{driver.id}</td>
                    </tr>
                  </table>
                </div>

                <div style="margin:20px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    <strong>✓ Registration Complete</strong> — The driver has been added to the system and received their welcome email.
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  This is an automated notification from the {settings.COMPANY_OPERATING_NAME} registration system.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {registered_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        office_text = (
            f"New Driver Registration on {settings.COMPANY_OPERATING_NAME}\n\n"
            f"Driver Name: {name}\n"
            f"Email: {email}\n"
            f"Phone: {phone_number}\n"
            f"Vehicle Number: {vehicle_number}\n"
            f"Registration Time: {registered_at}\n"
            f"Driver ID: {driver.id}\n\n"
            "The driver has been added to the system and received their welcome email.\n"
        )

        _send_html_email_help_desk(
            subject=f"New Driver Registration: {name}",
            to_email=settings.EMAIL_ADMIN_OFFICE,
            html=office_html,
            text_fallback=office_text,
        )
    except Exception:
        logger.exception("Failed to send office notification email for driver registration")

    return _ok(
        "Driver registration successful.",
        id=driver.id,
        email=driver.email,
        registered_at=registered_at
    )



@csrf_protect
@require_http_methods(["GET"])
@pharmacy_auth_required
def get_pharmacy_details(request: HttpRequest, pharmacy_id: int):
    """
    GET API: Returns all information of a pharmacy by pharmacyId.
    Example: /api/getPharmacyDetails/1/

    - DB timestamps are UTC
    - API response timestamps are converted to local timezone
      using settings.USER_TIMEZONE
    """
    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)

        # ---- Time handling (UTC → Local) ----
        created_at_utc = pharmacy.created_at
        try:
            created_at_local = created_at_utc.astimezone(settings.USER_TIMEZONE)
        except Exception:
            created_at_local = created_at_utc

        created_at_str = created_at_local.strftime("%Y-%m-%d %H:%M:%S")

        # ---- Business hours formatting (UNCHANGED) ----
        days_order = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        day_full = {
            "Mon": "Monday",
            "Tue": "Tuesday",
            "Wed": "Wednesday",
            "Thu": "Thursday",
            "Fri": "Friday",
            "Sat": "Saturday",
            "Sun": "Sunday",
        }

        business_hours = pharmacy.business_hours or {}
        formatted_lines = []

        for d in days_order:
            v = business_hours.get(d)
            if not v or v == "closed":
                formatted_lines.append(f"{day_full[d]}: Closed")
            else:
                open_t = v.get("open", "")
                close_t = v.get("close", "")
                formatted_lines.append(f"{day_full[d]}: {open_t} - {close_t}")

        # ---- Response (UNCHANGED STRUCTURE) ----
        return JsonResponse(
            {
                "success": True,
                "pharmacy": {
                    "id": pharmacy.id,
                    "name": pharmacy.name,
                    "store_address": pharmacy.store_address,
                    "city": pharmacy.city,
                    "province": pharmacy.province,
                    "postal_code": pharmacy.postal_code,
                    "country": pharmacy.country,
                    "phone_number": pharmacy.phone_number,
                    "email": pharmacy.email,
                    "created_at": created_at_str,

                    "business_hours_raw": business_hours,
                    "business_hours_formatted": formatted_lines,
                },
            },
            status=200,
        )

    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {"success": False, "error": "Pharmacy not found."},
            status=404,
        )

    except Exception:
        # Do NOT leak internals in prod
        return JsonResponse(
            {"success": False, "error": "Internal server error."},
            status=500,
        )



@csrf_protect
@require_http_methods(["POST"])
@pharmacy_auth_required
def change_existing_password(request):
    """
    POST API to change an existing pharmacy password.

    Request Body (JSON):
    {
        "pharmacyId": 1,
        "old_password": "current_pass",
        "new_password": "NewStrong#123"
    }

    Password Requirements:
    - At least 8 characters
    - Uppercase + lowercase
    - Number (0-9)
    - Special char (!@#$%^&*)
    """

    try:
        # ---------- Parse JSON ----------
        try:
            data = json.loads(request.body.decode("utf-8"))
        except Exception:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON body."},
                status=400
            )

        pharmacy_id = data.get("pharmacyId")
        old_password = (data.get("old_password") or "").strip()
        new_password = (data.get("new_password") or "").strip()

        if not pharmacy_id or not old_password or not new_password:
            return JsonResponse(
                {"success": False, "error": "Missing required fields."},
                status=400
            )

        # ---------- Auth safety ----------
        # pharmacy_auth_required already validated token
        if int(request.pharmacy.id) != int(pharmacy_id):
            return JsonResponse(
                {"success": False, "error": "Unauthorized action."},
                status=403
            )

        pharmacy = request.pharmacy

        # ---------- Verify old password ----------
        if not check_password(old_password, pharmacy.password):
            return JsonResponse(
                {"success": False, "error": "Incorrect old password."},
                status=401
            )

        # ---------- Password policy ----------
        if len(new_password) < 8:
            return JsonResponse(
                {"success": False, "error": "Password must be at least 8 characters long."},
                status=400
            )

        if not re.search(r"[A-Z]", new_password):
            return JsonResponse(
                {"success": False, "error": "Password must include at least one uppercase letter."},
                status=400
            )

        if not re.search(r"[a-z]", new_password):
            return JsonResponse(
                {"success": False, "error": "Password must include at least one lowercase letter."},
                status=400
            )

        if not re.search(r"[0-9]", new_password):
            return JsonResponse(
                {"success": False, "error": "Password must include at least one number (0-9)."},
                status=400
            )

        if not re.search(r"[!@#$%^&*]", new_password):
            return JsonResponse(
                {"success": False, "error": "Password must include at least one special character (!@#$%^&*)."},
                status=400
            )

        # Prevent reuse
        if check_password(new_password, pharmacy.password):
            return JsonResponse(
                {"success": False, "error": "New password must be different from the old password."},
                status=400
            )

        # ---------- Update password ----------
        pharmacy.password = make_password(new_password)
        pharmacy.save(update_fields=["password"])

        # ---------- Send email (non-blocking) ----------
        try:
            # Get current time in UTC (for DB storage if needed)
            utc_now = timezone.now()
            
            # Convert to user's local timezone for email display
            local_time = utc_now.astimezone(settings.USER_TIMEZONE)
            changed_at = local_time.strftime("%b %d, %Y %I:%M %p %Z")  # e.g., "Jan 03, 2026 02:30 PM EST"
            
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            logo_url = settings.LOGO_URL

            html_content = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed Successfully • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <!-- Hidden preheader -->
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your {settings.COMPANY_OPERATING_NAME} password was changed on {changed_at}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <!-- Card -->
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;" class="card">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left" style="vertical-align:middle;">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="40"
                        height="40"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Security Notification
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 10px 24px;">
                <h1 style="margin:0 0 10px 0;font:700 22px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Password Changed Successfully
                </h1>
                <p style="margin:0 0 16px 0;font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Your {settings.COMPANY_OPERATING_NAME} account password was changed on
                  <strong style="color:{brand_primary_dark}">{changed_at}</strong>.
                </p>

                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                       style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:14px 16px;">
                      <p style="margin:0 0 6px 0;font:400 13px/1.65 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        If <strong>you</strong> made this change, no further action is needed.
                      </p>
                      <p style="margin:0;font:400 13px/1.65 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        If this wasn't you, please reset your password immediately from the login page.
                      </p>
                    </td>
                  </tr>
                </table>

                <p style="margin:16px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For your security, never share your password with anyone.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px 24px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
                       style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Need help? Reply to this email and our team will assist you.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>

          <p style="margin:14px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {local_time.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

            text_content = (
                f"{settings.COMPANY_OPERATING_NAME} — Password Changed Successfully\n\n"
                f"Your password was changed on {changed_at}.\n\n"
                "If you did not perform this change, please reset your password immediately.\n\n"
                f"{settings.COMPANY_OPERATING_NAME} Support\n"
            )

            subject = f"Your {settings.COMPANY_OPERATING_NAME} Password Was Changed Successfully"
            
            _send_html_email_help_desk(
                subject=subject,
                to_email=pharmacy.email,
                html=html_content,
                text_fallback=text_content
            )
        except Exception as e:
            # Log the error but don't fail the password change
            print(f"Failed to send password change email: {str(e)}")

        return JsonResponse(
            {"success": True, "message": "Password changed successfully."},
            status=200
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500
        )

@csrf_protect
@require_http_methods(["POST"])
@pharmacy_auth_required
def edit_pharmacy_profile(request):
    """
    POST API to update pharmacy profile information (including business hours).
    
    Request Body (JSON):
    {
        "pharmacyId": 1,
        "name": "Updated Pharmacy Name",
        "store_address": "123 Main St",
        "city": "Toronto",
        "province": "ON",
        "postal_code": "M5H 2N2",
        "country": "Canada",
        "phone_number": "+1-416-555-0123",
        "email": "pharmacy@example.com",
        "business_hours": {
            "Mon": {"open": "09:00", "close": "17:00"},
            "Tue": {"open": "09:00", "close": "17:00"},
            "Wed": "closed",
            ...
        }
    }
    """
    try:
        # ---------- Parse JSON ----------
        try:
            data = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON body."},
                status=400
            )

        pharmacy_id = data.get("pharmacyId")

        if not pharmacy_id:
            return JsonResponse(
                {"success": False, "error": "pharmacyId is required."},
                status=400
            )

        # ---------- Auth safety ----------
        # pharmacy_auth_required already validated token
        if int(request.pharmacy.id) != int(pharmacy_id):
            return JsonResponse(
                {"success": False, "error": "Unauthorized action."},
                status=403
            )

        pharmacy = request.pharmacy

        # ---------- Editable fields ----------
        editable_fields = [
            "name",
            "store_address",
            "city",
            "province",
            "postal_code",
            "country",
            "phone_number",
            "email"
        ]

        updated_fields = []

        # ---------- Validate and update scalar fields ----------
        for field in editable_fields:
            if field in data:
                new_value = data[field]
                
                # Trim whitespace for string fields
                if isinstance(new_value, str):
                    new_value = new_value.strip()
                    
                    # Additional validation for specific fields
                    if field == "email" and new_value:
                        # Basic email validation
                        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", new_value):
                            return JsonResponse(
                                {"success": False, "error": "Invalid email format."},
                                status=400
                            )
                    
                    if field == "phone_number" and new_value:
                        # Remove spaces and validate phone has at least 10 digits
                        clean_phone = re.sub(r'\D', '', new_value)
                        if len(clean_phone) < 10:
                            return JsonResponse(
                                {"success": False, "error": "Phone number must have at least 10 digits."},
                                status=400
                            )
                    
                    if field == "postal_code" and new_value:
                        # Basic postal code validation (not empty)
                        if len(new_value) < 3:
                            return JsonResponse(
                                {"success": False, "error": "Invalid postal code."},
                                status=400
                            )
                
                # Check if value actually changed
                if getattr(pharmacy, field) != new_value:
                    setattr(pharmacy, field, new_value)
                    updated_fields.append(field)

        # ---------- Handle business hours separately ----------
        if "business_hours" in data:
            incoming_hours = data["business_hours"]

            # Validate business_hours structure
            if not isinstance(incoming_hours, dict):
                return JsonResponse(
                    {"success": False, "error": "business_hours must be an object."},
                    status=400
                )

            valid_days = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

            # Validate each day's hours
            for day, value in incoming_hours.items():
                if day not in valid_days:
                    return JsonResponse(
                        {"success": False, "error": f"Invalid day: {day}. Must be one of {valid_days}"},
                        status=400
                    )

                if value == "closed":
                    continue

                # Validate open/close format
                if not isinstance(value, dict) or "open" not in value or "close" not in value:
                    return JsonResponse(
                        {"success": False, "error": f"Invalid hours format for {day}. Expected {{\"open\": \"HH:MM\", \"close\": \"HH:MM\"}} or \"closed\"."},
                        status=400
                    )

                # Validate time format (HH:MM)
                time_pattern = r"^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$"
                if not re.match(time_pattern, value["open"]) or not re.match(time_pattern, value["close"]):
                    return JsonResponse(
                        {"success": False, "error": f"Invalid time format for {day}. Use HH:MM format (e.g., 09:00, 17:30)."},
                        status=400
                    )

                # Validate that close time is after open time
                open_time = datetime.strptime(value["open"], "%H:%M").time()
                close_time = datetime.strptime(value["close"], "%H:%M").time()
                
                if close_time <= open_time:
                    return JsonResponse(
                        {"success": False, "error": f"Close time must be after open time for {day}."},
                        status=400
                    )

            # Check if business hours actually changed
            if pharmacy.business_hours != incoming_hours:
                pharmacy.business_hours = incoming_hours
                updated_fields.append("business_hours")

        # ---------- Check if any changes were made ----------
        if not updated_fields:
            return JsonResponse(
                {"success": False, "message": "No fields were changed."},
                status=200
            )

        # ---------- Save changes with timezone awareness ----------
        # Django auto-updates `updated_at` if you have auto_now=True
        # The timestamp is stored in UTC by default
        pharmacy.save(update_fields=updated_fields)

        # ---------- Convert timestamps to local timezone for response ----------
        utc_now = timezone.now()
        local_time = utc_now.astimezone(settings.USER_TIMEZONE)
        updated_at_local = local_time.strftime("%b %d, %Y %I:%M %p %Z")

        return JsonResponse({
            "success": True,
            "message": "Profile updated successfully.",
            "updated_fields": updated_fields,
            "updated_at": updated_at_local
        }, status=200)

    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {"success": False, "error": "Pharmacy not found."},
            status=404
        )
    except ValueError as ve:
        return JsonResponse(
            {"success": False, "error": f"Validation error: {str(ve)}"},
            status=400
        )
    except Exception as e:
        # Log the error in production
        print(f"Error in edit_pharmacy_profile: {str(e)}")
        return JsonResponse(
            {"success": False, "error": "An error occurred while updating profile."},
            status=500
        )




def get_cache_key(addresses):
    """Generate cache key for distance matrix"""
    addr_str = "|".join(sorted(addresses))
    return f"dist_matrix_{hashlib.md5(addr_str.encode()).hexdigest()}"


def get_distance_matrix_parallel(gmaps, addresses):
    """
    Fetch distance matrix with parallel batch requests and caching.
    This significantly reduces API call time.
    """
    # Check cache first
    cache_key = get_cache_key(addresses)
    cached_matrix = cache.get(cache_key)
    if cached_matrix:
        logger.info(f"Using cached distance matrix for {len(addresses)} addresses")
        return cached_matrix
    
    n = len(addresses)
    distance_matrix = [[999999 for _ in range(n)] for _ in range(n)]
    batch_size = 10
    
    def fetch_batch(i, j):
        """Fetch a single batch"""
        origins = addresses[i:min(i + batch_size, n)]
        destinations = addresses[j:min(j + batch_size, n)]
        
        try:
            matrix = gmaps.distance_matrix(
                origins,
                destinations,
                mode="driving",
                units="metric",
                departure_time="now"  # Use real-time traffic
            )
            
            if matrix.get("status") != "OK":
                logger.error(f"Batch request failed: {matrix.get('status')}")
                return None
            
            return (i, j, matrix)
            
        except Exception as e:
            logger.error(f"Error fetching batch ({i}, {j}): {str(e)}")
            return None
    
    # Create batch requests
    batch_requests = []
    for i in range(0, n, batch_size):
        for j in range(0, n, batch_size):
            batch_requests.append((i, j))
    
    logger.info(f"Fetching {len(batch_requests)} batches in parallel for {n} addresses")
    
    # Execute batches in parallel (max 5 concurrent to respect API limits)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_batch, i, j): (i, j) for i, j in batch_requests}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                i, j, matrix = result
                
                # Fill in the distance matrix
                for row_idx, row in enumerate(matrix.get("rows", [])):
                    for col_idx, elem in enumerate(row.get("elements", [])):
                        actual_i = i + row_idx
                        actual_j = j + col_idx
                        
                        if elem.get("status") == "OK":
                            distance_value = elem.get("distance", {}).get("value", 999999)
                            distance_matrix[actual_i][actual_j] = distance_value
                        else:
                            distance_matrix[actual_i][actual_j] = 999999
    
    # Cache for 1 hour
    cache.set(cache_key, distance_matrix, 3600)
    logger.info(f"Distance matrix cached successfully")
    
    return distance_matrix


def normalize_address(address):
    """Normalize address for comparison (remove extra spaces, lowercase)"""
    if not address:
        return ""
    return " ".join(address.lower().strip().split())


def consolidate_consecutive_stops(stops):
    """
    Consolidate consecutive stops at the same address into single stops with multiple order_ids.
    
    Example input:
    [
        {"kind": "pickup", "address": "535 Park St", "order_id": 39, "date": "2025-11-04", "leg_distance_km": 0.0},
        {"kind": "pickup", "address": "535 Park St", "order_id": 35, "date": "2025-11-04", "leg_distance_km": 18.66}
    ]
    
    Example output:
    [
        {"kind": "pickup", "address": "535 Park St", "order_ids": [39, 35], "date": "2025-11-04", "leg_distance_km": 18.66}
    ]
    """
    if not stops:
        return []
    
    consolidated = []
    current_group = None
    
    for stop in stops:
        # Normalize address for comparison
        normalized_addr = normalize_address(stop["address"])
        
        # Check if this stop can be merged with current group
        if (current_group and 
            current_group["kind"] == stop["kind"] and
            normalize_address(current_group["address"]) == normalized_addr and
            current_group["date"] == stop["date"]):
            
            # Merge into current group
            if stop["order_id"] is not None:
                current_group["order_ids"].append(stop["order_id"])
            
            # Keep the leg_distance from the LAST stop in the group (when we leave)
            current_group["leg_distance_km"] = stop["leg_distance_km"]
        else:
            # Start new group
            if current_group:
                consolidated.append(current_group)
            
            current_group = {
                "kind": stop["kind"],
                "address": stop["address"],  # Keep original formatting
                "order_ids": [stop["order_id"]] if stop["order_id"] is not None else [],
                "date": stop["date"],
                "leg_distance_km": stop["leg_distance_km"]
            }
    
    # Add last group
    if current_group:
        consolidated.append(current_group)
    
    logger.info(f"Consolidated {len(stops)} stops into {len(consolidated)} grouped stops")
    return consolidated


def solve_single_date_group(date_key, date_deliveries, start_location, gmaps):
    """
    Solve optimization for a single date group.
    Extracted to allow parallel processing if needed.
    """
    logger.info(f"Optimizing {len(date_deliveries)} deliveries for date: {date_key}")
    
    # Build addresses list
    addresses = [start_location]
    pickup_indices = []
    drop_indices = []
    order_ids = []
    
    for d in date_deliveries:
        pickup_indices.append(len(addresses))
        addresses.append(d["pickup_address"])
        drop_indices.append(len(addresses))
        addresses.append(d["dropoff_address"])
        order_ids.append(d.get("order_id"))
    
    n = len(addresses)
    logger.info(f"Date {date_key}: {n} addresses (1 start + {len(pickup_indices)} pickups + {len(drop_indices)} dropoffs)")

    # Get distance matrix with caching and parallelization
    try:
        distance_matrix = get_distance_matrix_parallel(gmaps, addresses)
    except Exception as e:
        logger.error(f"Distance matrix error for date {date_key}: {str(e)}")
        raise

    # Validate matrix
    if len(distance_matrix) != n or any(len(row) != n for row in distance_matrix):
        raise ValueError("Invalid distance matrix dimensions")

    # Initialize OR-Tools Routing Model
    manager = pywrapcp.RoutingIndexManager(n, 1, 0)
    routing = pywrapcp.RoutingModel(manager)

    def distance_callback(from_index, to_index):
        f = manager.IndexToNode(from_index)
        t = manager.IndexToNode(to_index)
        return distance_matrix[f][t]

    transit_cb = routing.RegisterTransitCallback(distance_callback)
    routing.SetArcCostEvaluatorOfAllVehicles(transit_cb)

    # Add Distance dimension
    routing.AddDimension(
        transit_cb,
        0,
        10000000,
        True,
        "Distance"
    )
    distance_dim = routing.GetDimensionOrDie("Distance")

    # Add pickup-delivery constraints
    for idx, (p, d) in enumerate(zip(pickup_indices, drop_indices)):
        pickup_idx = manager.NodeToIndex(p)
        delivery_idx = manager.NodeToIndex(d)
        
        routing.AddPickupAndDelivery(pickup_idx, delivery_idx)
        routing.solver().Add(
            routing.VehicleVar(pickup_idx) == routing.VehicleVar(delivery_idx)
        )
        routing.solver().Add(
            distance_dim.CumulVar(pickup_idx) <= distance_dim.CumulVar(delivery_idx)
        )

    logger.info(f"Added {len(pickup_indices)} pickup-delivery constraints for date {date_key}")

    # Optimized solver parameters - faster but still good quality
    search_params = pywrapcp.DefaultRoutingSearchParameters()
    search_params.first_solution_strategy = routing_enums_pb2.FirstSolutionStrategy.PATH_CHEAPEST_ARC
    search_params.local_search_metaheuristic = routing_enums_pb2.LocalSearchMetaheuristic.GUIDED_LOCAL_SEARCH
    
    # Adaptive timeout based on problem size
    timeout = min(15 + (n // 10), 30)  # 15-30 seconds based on size
    search_params.time_limit.seconds = timeout
    
    # Limit solution attempts for faster response
    search_params.solution_limit = 50

    logger.info(f"Solving route for date {date_key} with {timeout}s timeout...")
    solution = routing.SolveWithParameters(search_params)
    
    if not solution:
        raise ValueError(f"No feasible route found for date {date_key}")

    logger.info(f"Solution found for date {date_key}! Building route...")

    # Build metadata map
    node_meta = {0: {"kind": "start", "order_id": None, "date": date_key}}
    addr_i = 1
    for idx, order_id in enumerate(order_ids):
        node_meta[addr_i] = {"kind": "pickup", "order_id": order_id, "date": date_key}
        addr_i += 1
        node_meta[addr_i] = {"kind": "dropoff", "order_id": order_id, "date": date_key}
        addr_i += 1

    # Extract optimized route
    index = routing.Start(0)
    date_stops = []
    date_distance = 0
    last_address = None
    
    while not routing.IsEnd(index):
        node = manager.IndexToNode(index)
        meta = node_meta.get(node, {"kind": "unknown", "order_id": None, "date": date_key})
        next_index = solution.Value(routing.NextVar(index))
        next_node = manager.IndexToNode(next_index)
        
        if node < len(distance_matrix) and next_node < len(distance_matrix[node]):
            leg_distance = distance_matrix[node][next_node]
        else:
            leg_distance = 0
        
        date_distance += leg_distance
        last_address = addresses[node]
        
        date_stops.append({
            "kind": meta["kind"],
            "address": addresses[node],
            "order_id": meta["order_id"],
            "date": meta["date"],
            "leg_distance_km": round(leg_distance / 1000, 2)
        })
        
        index = next_index
    
    logger.info(f"✓ Date {date_key}: {len(date_stops)} stops, {round(date_distance/1000, 2)}km")
    
    return {
        "stops": date_stops,
        "distance": date_distance,
        "last_address": last_address
    }


# @csrf_exempt
# @require_http_methods(["POST"])
# def optimize_route_api(request):
#     """
#     Optimized delivery route API with:
#     - Parallel distance matrix fetching
#     - Distance matrix caching
#     - Adaptive solver timeouts
#     - Better error handling
#     - Consolidated consecutive same-address stops
#     """
#     try:
#         data = json.loads(request.body)
#         driver_start = data.get("driver_start")
#         deliveries = data.get("deliveries", [])

#         logger.info(f"Received optimization request: driver_start={driver_start}, deliveries={len(deliveries)}")

#         if not driver_start or not deliveries:
#             return JsonResponse({"error": "Missing required data", "success": False}, status=400)

#         if not isinstance(deliveries, list) or len(deliveries) == 0:
#             return JsonResponse({"error": "No deliveries provided", "success": False}, status=400)

#         # Use secure Google Maps API key
#         api_key = settings.GOOGLE_MAPS_API_KEY
#         if not api_key:
#             logger.error("Google Maps API key not configured")
#             return JsonResponse({"error": "API key not configured", "success": False}, status=500)

#         gmaps = googlemaps.Client(key=api_key)

#         # Group deliveries by pickup date
#         deliveries_by_date = defaultdict(list)
#         from datetime import datetime, date
#         today = date.today()
        
#         for d in deliveries:
#             if not d.get("pickup_address") or not d.get("dropoff_address"):
#                 logger.warning(f"Skipping delivery with missing address: {d}")
#                 continue
            
#             # Extract date from pickup_date
#             pickup_date = d.get("pickup_date", "unknown")
#             if isinstance(pickup_date, str) and 'T' in pickup_date:
#                 pickup_date = pickup_date.split('T')[0]
            
#             # Skip past dates
#             try:
#                 delivery_date = datetime.strptime(pickup_date, '%Y-%m-%d').date()
#                 if delivery_date < today:
#                     logger.info(f"Skipping past date delivery: {pickup_date} for order {d.get('order_id')}")
#                     continue
#             except:
#                 logger.warning(f"Invalid date format: {pickup_date}, including in optimization")
            
#             deliveries_by_date[pickup_date].append(d)
        
#         if len(deliveries_by_date) == 0:
#             return JsonResponse({
#                 "error": "No current or future deliveries to optimize", 
#                 "success": False
#             }, status=400)
        
#         logger.info(f"Grouped {sum(len(v) for v in deliveries_by_date.values())} deliveries into {len(deliveries_by_date)} date groups")

#         # Process each date group
#         all_stops = []
#         total_distance = 0
#         current_location = driver_start

#         # Sort dates chronologically
#         sorted_dates = sorted(deliveries_by_date.keys())
        
#         for idx, date_key in enumerate(sorted_dates):
#             date_deliveries = deliveries_by_date[date_key]
            
#             try:
#                 result = solve_single_date_group(date_key, date_deliveries, current_location, gmaps)
                
#                 # Skip start point after first date group
#                 if idx > 0 and result["stops"][0]["kind"] == "start":
#                     result["stops"] = result["stops"][1:]
                
#                 all_stops.extend(result["stops"])
#                 total_distance += result["distance"]
#                 current_location = result["last_address"]
                
#             except Exception as e:
#                 logger.error(f"Error optimizing date {date_key}: {str(e)}")
#                 return JsonResponse({
#                     "error": f"Failed to optimize route for {date_key}: {str(e)}", 
#                     "success": False
#                 }, status=500)

#         # Consolidate consecutive stops at same address
#         consolidated_stops = consolidate_consecutive_stops(all_stops)

#         logger.info(f"✓✓ FULL ROUTE OPTIMIZED: {len(consolidated_stops)} total stops (consolidated from {len(all_stops)}), {round(total_distance/1000, 2)}km across {len(deliveries_by_date)} dates")

#         return JsonResponse({
#             "success": True,
#             "stops": consolidated_stops,
#             "total_distance_km": round(total_distance / 1000, 2),
#             "dates_optimized": len(deliveries_by_date)
#         })

#     except json.JSONDecodeError as e:
#         logger.error(f"JSON decode error: {str(e)}")
#         return JsonResponse({"error": "Invalid JSON payload", "success": False}, status=400)
#     except Exception as e:
#         logger.exception(f"Unexpected error in route optimization: {str(e)}")
#         return JsonResponse({"error": f"Internal server error: {str(e)}", "success": False}, status=500)


@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def optimize_route_api(request):
    """
    Optimized delivery route API with:
    - Driver authentication (JWT token)
    - CSRF protection
    - Timezone awareness (settings.USER_TIMEZONE)
    - Parallel distance matrix fetching
    - Distance matrix caching
    - Adaptive solver timeouts
    - Better error handling
    - Consolidated consecutive same-address stops
    
    Request Body (JSON):
    {
        "driver_start": "123 Main St, City, Province",
        "deliveries": [
            {
                "order_id": 123,
                "pickup_address": "456 Oak Ave, City",
                "dropoff_address": "789 Pine St, City",
                "pickup_date": "2026-01-15T10:00:00Z"
            },
            ...
        ]
    }
    
    Response:
    {
        "success": true,
        "stops": [
            {
                "kind": "start|pickup|dropoff",
                "address": "...",
                "order_ids": [123, 124],
                "date": "2026-01-15",
                "leg_distance_km": 5.2
            },
            ...
        ],
        "total_distance_km": 45.8,
        "dates_optimized": 3,
        "optimized_at": "Jan 03, 2026 02:30 PM EST"
    }
    """
    try:
        # ---------- Parse JSON ----------
        try:
            data = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return JsonResponse({
                "success": False,
                "error": "Invalid JSON payload"
            }, status=400)

        driver_start = data.get("driver_start")
        deliveries = data.get("deliveries", [])

        # ---------- Input Validation ----------
        if not driver_start or not isinstance(driver_start, str):
            return JsonResponse({
                "success": False,
                "error": "driver_start address is required"
            }, status=400)

        driver_start = driver_start.strip()
        if len(driver_start) < 5:
            return JsonResponse({
                "success": False,
                "error": "Invalid driver_start address"
            }, status=400)

        if not isinstance(deliveries, list) or len(deliveries) == 0:
            return JsonResponse({
                "success": False,
                "error": "No deliveries provided"
            }, status=400)

        # Limit maximum deliveries per request (prevent abuse)
        if len(deliveries) > 100:
            return JsonResponse({
                "success": False,
                "error": "Maximum 100 deliveries per request"
            }, status=400)

        # Validate each delivery
        validated_deliveries = []
        for idx, d in enumerate(deliveries):
            if not isinstance(d, dict):
                return JsonResponse({
                    "success": False,
                    "error": f"Delivery {idx} must be an object"
                }, status=400)

            pickup = d.get("pickup_address", "").strip()
            dropoff = d.get("dropoff_address", "").strip()

            if not pickup or not dropoff:
                return JsonResponse({
                    "success": False,
                    "error": f"Delivery {idx} missing pickup or dropoff address"
                }, status=400)

            if len(pickup) < 5 or len(dropoff) < 5:
                return JsonResponse({
                    "success": False,
                    "error": f"Delivery {idx} has invalid address format"
                }, status=400)

            # Create validated delivery with formatted addresses
            validated_deliveries.append({
                "order_id": d.get("order_id"),
                "pickup_address": pickup,
                "dropoff_address": dropoff,
                "pickup_date": d.get("pickup_date", "unknown")
            })

        logger.info(f"Driver {request.driver.id} optimization request: {len(validated_deliveries)} deliveries")

        # ---------- Google Maps API ----------
        api_key = settings.GOOGLE_MAPS_API_KEY
        if not api_key:
            logger.error("Google Maps API key not configured")
            return JsonResponse({
                "success": False,
                "error": "Service temporarily unavailable"
            }, status=500)

        gmaps = googlemaps.Client(key=api_key)

        # ---------- Timezone-aware date filtering ----------
        # Get current date in user's timezone
        utc_now = timezone.now()
        local_now = utc_now.astimezone(settings.USER_TIMEZONE)
        today = local_now.date()

        logger.info(f"Current date in {settings.USER_TIMEZONE}: {today}")

        # ---------- Group deliveries by pickup date ----------
        deliveries_by_date = defaultdict(list)
        
        for d in validated_deliveries:
            if not d.get("pickup_address") or not d.get("dropoff_address"):
                logger.warning(f"Skipping delivery with missing address: order_id={d.get('order_id')}")
                continue
            
            # Extract date from pickup_date
            pickup_date_str = d.get("pickup_date", "unknown")
            
            # Handle ISO format with timezone
            if isinstance(pickup_date_str, str):
                if 'T' in pickup_date_str:
                    pickup_date_str = pickup_date_str.split('T')[0]
            
            # Skip past dates (using local timezone)
            try:
                delivery_date = datetime.strptime(pickup_date_str, '%Y-%m-%d').date()
                if delivery_date < today:
                    logger.info(f"Skipping past date delivery: {pickup_date_str} for order {d.get('order_id')}")
                    continue
            except (ValueError, AttributeError) as e:
                logger.warning(f"Invalid date format '{pickup_date_str}' for order {d.get('order_id')}: {str(e)}")
                continue
            
            deliveries_by_date[pickup_date_str].append(d)
        
        if len(deliveries_by_date) == 0:
            return JsonResponse({
                "success": False,
                "error": "No current or future deliveries to optimize"
            }, status=400)
        
        logger.info(f"Grouped {sum(len(v) for v in deliveries_by_date.values())} deliveries into {len(deliveries_by_date)} date groups")

        # ---------- Process each date group ----------
        all_stops = []
        total_distance = 0
        current_location = driver_start

        # Sort dates chronologically
        sorted_dates = sorted(deliveries_by_date.keys())
        
        for idx, date_key in enumerate(sorted_dates):
            date_deliveries = deliveries_by_date[date_key]
            
            try:
                result = solve_single_date_group(date_key, date_deliveries, current_location, gmaps)
                
                # Skip start point after first date group
                if idx > 0 and result["stops"][0]["kind"] == "start":
                    result["stops"] = result["stops"][1:]
                
                all_stops.extend(result["stops"])
                total_distance += result["distance"]
                current_location = result["last_address"]
                
            except Exception as e:
                logger.error(f"Error optimizing date {date_key}: {str(e)}")
                return JsonResponse({
                    "success": False,
                    "error": f"Failed to optimize route for {date_key}"
                }, status=500)

        # ---------- Consolidate consecutive stops ----------
        consolidated_stops = consolidate_consecutive_stops(all_stops)

        # ---------- Timezone-aware response timestamp ----------
        optimized_at_local = local_now.strftime("%b %d, %Y %I:%M %p %Z")

        logger.info(f"✓✓ FULL ROUTE OPTIMIZED for Driver {request.driver.id}: {len(consolidated_stops)} total stops (consolidated from {len(all_stops)}), {round(total_distance/1000, 2)}km across {len(deliveries_by_date)} dates")

        return JsonResponse({
            "success": True,
            "stops": consolidated_stops,
            "total_distance_km": round(total_distance / 1000, 2),
            "dates_optimized": len(deliveries_by_date),
            "optimized_at": optimized_at_local
        }, status=200)

    except Exception as e:
        logger.exception(f"Unexpected error in route optimization for driver {getattr(request, 'driver', 'unknown')}")
        return JsonResponse({
            "success": False,
            "error": "An error occurred while optimizing the route"
        }, status=500)


@require_POST
@csrf_protect
def admin_login(request):
    """
    Authenticates an admin user and sets JWT in an HttpOnly secure cookie.
    """

    # 1️⃣ Parse request body
    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")
    except Exception:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON"},
            status=400
        )

    if not email or not password:
        return JsonResponse(
            {"success": False, "message": "Email and password required"},
            status=400
        )

    # 2️⃣ Fetch admin (case-insensitive email match)
    try:
        admin = AdminUser.objects.get(email__iexact=email.strip())
    except AdminUser.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Invalid credentials"},
            status=401
        )

    # 3️⃣ Verify password
    password_valid = False
    if admin.password:
        if admin.password.startswith("pbkdf2_"):
            password_valid = check_password(password, admin.password)
        else:
            # Legacy/plain-text fallback
            password_valid = (admin.password == password)

    if not password_valid:
        return JsonResponse(
            {"success": False, "message": "Invalid credentials"},
            status=401
        )

    # 4️⃣ Create JWT payload
    issued_at = timezone.now()  # UTC
    expires_at = issued_at + timedelta(hours=settings.JWT_EXPIRY_HOURS)

    payload = {
        "admin_id": admin.id,
        "email": admin.email,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    # 5️⃣ Build response (NO token in JSON)
    response = JsonResponse({
        "success": True,
        "id": admin.id,
        "message": "Login successful",
        "first_name": admin.first_name,
        "last_name": admin.last_name,
        "email": admin.email,
        "expiresAt": timezone.localtime(
            expires_at,
            settings.USER_TIMEZONE
        ).isoformat(),
    })

    # 6️⃣ Set secure HttpOnly cookie (authToken)
    response.set_cookie(
        key="authToken",
        value=token,
        max_age=settings.JWT_EXPIRY_HOURS * 60 * 60,
        httponly=True,                 # 🔐 JS cannot read
        secure=settings.SECURE_SSL_REDIRECT,  # 🔐 HTTPS only
        samesite="Lax",                # 🛡 CSRF protection
        path="/",
    )

    # 7️⃣ Set adminId cookie (readable by JS for convenience)
    response.set_cookie(
        key="adminId",
        value=str(admin.id),
        max_age=settings.JWT_EXPIRY_HOURS * 60 * 60,  # ⚠️ Same expiration as authToken
        httponly=False,                # ✅ JS can read this
        secure=settings.SECURE_SSL_REDIRECT,  # 🔐 HTTPS only
        samesite="Lax",                # 🛡 CSRF protection
        path="/",
    )

    return response



@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def admin_dashboard_stats(request):
    try:
        # 🌍 Timezone setup
        user_tz = settings.USER_TIMEZONE  # America/Toronto
        now_utc = timezone.now()
        now_local = now_utc.astimezone(user_tz)

        today_local_date = now_local.date()

        # 📅 Local month boundaries
        month_start_local = now_local.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )

        if month_start_local.month == 12:
            next_month_start_local = month_start_local.replace(
                year=month_start_local.year + 1, month=1
            )
        else:
            next_month_start_local = month_start_local.replace(
                month=month_start_local.month + 1
            )

        # Convert local boundaries → UTC for DB queries
        month_start_utc = month_start_local.astimezone(pytz.UTC)
        next_month_start_utc = next_month_start_local.astimezone(pytz.UTC)

        # 1️⃣ Active pharmacies & drivers
        total_pharmacies = Pharmacy.objects.filter(active=True).count()
        total_drivers = Driver.objects.filter(active=True).count()

        # 2️⃣ Order counts by status (REAL-TIME)
        order_status_counts = {
            "pending": DeliveryOrder.objects.filter(status="pending").count(),
            "accepted": DeliveryOrder.objects.filter(status="accepted").count(),
            "inTransit": DeliveryOrder.objects.filter(status="inTransit").count(),
            "picked_up": DeliveryOrder.objects.filter(status="picked_up").count(),
            "delivered": DeliveryOrder.objects.filter(status="delivered").count(),
            "cancelled": DeliveryOrder.objects.filter(status="cancelled").count(),
        }

        # 3️⃣ Gross revenue this month (DELIVERED only, LOCAL month window)
        revenue_this_month = (
            DeliveryOrder.objects.filter(
                status="delivered",
                delivered_at__gte=month_start_utc,
                delivered_at__lt=next_month_start_utc,
            ).aggregate(total=Sum("rate"))["total"] or 0
        )

        # 4️⃣ Driver payouts this month (invoice-based – correct as-is)
        driver_payout_this_month = (
            DriverInvoice.objects.filter(
                Q(start_date__year=now_local.year, start_date__month=now_local.month)
                | Q(end_date__year=now_local.year, end_date__month=now_local.month)
            ).aggregate(total=Sum("total_amount"))["total"] or 0
        )

        # 5️⃣ Delayed orders
        # pickup_day < today (LOCAL) AND not picked up yet
        delayed_orders_count = DeliveryOrder.objects.filter(
            pickup_day__lt=today_local_date,
            status__in=["pending", "accepted"]
        ).count()

        # 6️⃣ Today's orders (created today in LOCAL time)
        today_start_local = now_local.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        today_end_local = today_start_local + timedelta(days=1)

        today_start_utc = today_start_local.astimezone(pytz.UTC)
        today_end_utc = today_end_local.astimezone(pytz.UTC)

        todays_orders_count = DeliveryOrder.objects.filter(
            created_at__gte=today_start_utc,
            created_at__lt=today_end_utc
        ).count()

        # ✅ Response
        return JsonResponse(
            {
                "success": True,
                "timezone": str(user_tz),
                "metrics": {
                    "total_pharmacies": total_pharmacies,
                    "total_drivers": total_drivers,

                    "order_status_counts": order_status_counts,

                    "revenue_this_month": float(revenue_this_month),
                    "driver_payout_this_month": float(driver_payout_this_month),

                    "delayed_orders": delayed_orders_count,
                    "todays_orders": todays_orders_count,
                }
            },
            status=200
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500
        )



# @csrf_exempt
# def recent_activity_feed(request):
#     """
#     Returns a unified feed of the most recent 8 activity items across
#     Orders, Invoices, Drivers, Pharmacies, and Support Tickets.
#     Ensures a balanced mix from different tables.
#     """
#     try:
#         # Helper to safely slice even when fewer items exist
#         def safe_slice(qs, n): 
#             return list(qs[:n])

#         # 1️⃣ Recent Orders
#         orders = safe_slice(
#             DeliveryOrder.objects.select_related("pharmacy", "driver")
#             .order_by("-created_at"), 3
#         )
#         order_feed = [{
#             "type": "Order",
#             "title": f"Order #{o.id} ({o.status})",
#             "description": f"Placed by {o.pharmacy.name}. "
#                            f"Driver: {o.driver.name if o.driver else 'Unassigned'}",
#             "timestamp": o.created_at,
#         } for o in orders]

#         # 2️⃣ Recent Pharmacy Invoices
#         invoices = safe_slice(
#             Invoice.objects.select_related("pharmacy")
#             .order_by("-created_at"), 2
#         )
#         invoice_feed = [{
#             "type": "Pharmacy Invoice",
#             "title": f"Invoice #{inv.id} ({inv.status})",
#             "description": f"Generated for {inv.pharmacy.name} "
#                            f"(${inv.total_amount}, {inv.total_orders} orders)",
#             "timestamp": inv.created_at,
#         } for inv in invoices]

#         # 3️⃣ Recent Driver Invoices
#         driver_invoices = safe_slice(
#             DriverInvoice.objects.select_related("driver")
#             .order_by("-created_at"), 1
#         )
#         driver_invoice_feed = [{
#             "type": "Driver Invoice",
#             "title": f"Driver Invoice #{d.id} ({d.status})",
#             "description": f"For driver {d.driver.name}, total ${d.total_amount}",
#             "timestamp": d.created_at,
#         } for d in driver_invoices]

#         # 4️⃣ Recently Registered Pharmacies
#         pharmacies = safe_slice(
#             Pharmacy.objects.order_by("-created_at"), 1
#         )
#         pharmacy_feed = [{
#             "type": "New Pharmacy",
#             "title": f"{p.name} joined {settings.COMPANY_OPERATING_NAME}",
#             "description": f"Located in {p.city}, {p.province}",
#             "timestamp": p.created_at,
#         } for p in pharmacies]

#         # 5️⃣ Recently Registered Drivers
#         drivers = safe_slice(
#             Driver.objects.order_by("-created_at"), 1
#         )
#         driver_feed = [{
#             "type": "New Driver",
#             "title": f"{d.name} registered as driver",
#             "description": f"Vehicle #{d.vehicle_number or 'N/A'}",
#             "timestamp": d.created_at,
#         } for d in drivers]

#         # 6️⃣ Recent Support Tickets
#         tickets = safe_slice(
#             ContactAdmin.objects.select_related("pharmacy", "driver")
#             .order_by("-created_at"), 2
#         )
#         ticket_feed = [{
#             "type": "Support Ticket",
#             "title": f"{t.get_subject_display()} ({t.status})",
#             "description": f"From {t.pharmacy.name if t.pharmacy else t.driver.name if t.driver else 'Unknown'}",
#             "timestamp": t.created_at,
#         } for t in tickets]

#         # Combine all feeds
#         combined = list(chain(
#             order_feed, invoice_feed, driver_invoice_feed,
#             pharmacy_feed, driver_feed, ticket_feed
#         ))

#         # Sort by timestamp (latest first)
#         combined.sort(key=lambda x: x["timestamp"], reverse=True)

#         # Take only the most recent 8 items overall
#         recent_8 = combined[:8]

#         # Convert datetime to ISO
#         for item in recent_8:
#             item["timestamp"] = item["timestamp"].isoformat()

#         return JsonResponse({
#             "success": True,
#             "recent_activity": recent_8,
#             "count": len(recent_8),
#             "generated_at": now().isoformat()
#         })

#     except Exception as e:
#         return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def recent_activity_feed(request):
    """
    Admin Recent Activity (Event Feed)
    - Secure (CSRF + Admin Auth)
    - GET only
    - Event-based (what just happened)
    - Local timezone aware
    - Balanced mix across business entities
    """

    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    now_local = timezone.localtime(now_utc, user_tz)

    MAX_ITEMS = 8

    def to_local_iso(dt):
        if not dt:
            return None
        return timezone.localtime(dt, user_tz).isoformat()

    # Helper: fetch slightly more than needed to avoid ordering gaps
    def fetch(qs, n):
        return list(qs[:n])

    feed_items = []

    # 1️⃣ Order Placed events
    orders = fetch(
        DeliveryOrder.objects.select_related("pharmacy", "driver")
        .order_by("-created_at"),
        5
    )
    for o in orders:
        feed_items.append({
            "event": "order_created",
            "type": "Order",
            "title": f"Order #{o.id} placed",
            "description": (
                f"Placed by {o.pharmacy.name}. "
                f"Driver: {o.driver.name if o.driver else 'Unassigned'}"
            ),
            "timestamp": o.created_at,
        })

    # 2️⃣ Pharmacy Invoice Generated events
    invoices = fetch(
        Invoice.objects.select_related("pharmacy")
        .order_by("-created_at"),
        4
    )
    for inv in invoices:
        feed_items.append({
            "event": "invoice_generated",
            "type": "Pharmacy Invoice",
            "title": f"Invoice #{inv.id} generated",
            "description": (
                f"For {inv.pharmacy.name} "
                f"(${float(inv.total_amount):.2f}, {inv.total_orders} orders)"
            ),
            "timestamp": inv.created_at,
        })

    # 3️⃣ Driver Invoice Generated events
    driver_invoices = fetch(
        DriverInvoice.objects.select_related("driver")
        .order_by("-created_at"),
        3
    )
    for di in driver_invoices:
        feed_items.append({
            "event": "driver_invoice_generated",
            "type": "Driver Invoice",
            "title": f"Driver invoice #{di.id} generated",
            "description": (
                f"For driver {di.driver.name}, "
                f"amount ${float(di.total_amount):.2f}"
            ),
            "timestamp": di.created_at,
        })

    # 4️⃣ New Pharmacy Registered events
    pharmacies = fetch(
        Pharmacy.objects.order_by("-created_at"),
        2
    )
    for p in pharmacies:
        feed_items.append({
            "event": "pharmacy_registered",
            "type": "Pharmacy",
            "title": f"{p.name} joined {settings.COMPANY_OPERATING_NAME}",
            "description": f"Located in {p.city}, {p.province}",
            "timestamp": p.created_at,
        })

    # 5️⃣ New Driver Registered events
    drivers = fetch(
        Driver.objects.order_by("-created_at"),
        2
    )
    for d in drivers:
        feed_items.append({
            "event": "driver_registered",
            "type": "Driver",
            "title": f"{d.name} registered as a driver",
            "description": f"Vehicle: {d.vehicle_number or 'N/A'}",
            "timestamp": d.created_at,
        })

    # 6️⃣ Support Ticket Created events
    tickets = fetch(
        ContactAdmin.objects.select_related("pharmacy", "driver")
        .order_by("-created_at"),
        4
    )
    for t in tickets:
        sender = (
            t.pharmacy.name if t.pharmacy_id
            else t.driver.name if t.driver_id
            else "Unknown"
        )
        subject_display = (
            t.other_subject if (t.subject == "other" and t.other_subject)
            else t.get_subject_display()
        )

        feed_items.append({
            "event": "support_ticket_created",
            "type": "Support Ticket",
            "title": f"{subject_display} ticket created",
            "description": f"From {sender}",
            "timestamp": t.created_at,
        })

    # ----------------------------
    # Final ordering & shaping
    # ----------------------------
    feed_items.sort(key=lambda x: x["timestamp"], reverse=True)
    recent_items = feed_items[:MAX_ITEMS]

    # Convert timestamps to local ISO
    for item in recent_items:
        item["timestamp_local"] = to_local_iso(item.pop("timestamp"))

    return JsonResponse(
        {
            "success": True,
            "recent_activity": recent_items,
            "count": len(recent_items),
            "timezone": str(user_tz),
            "generated_at_local": now_local.isoformat(),
        },
        status=200
    )



@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def order_tracking_overview(request):
    """
    Returns a detailed list of all delivery orders
    with their tracking history and proof images.

    - Admin only
    - Read-only
    - All timestamps returned in LOCAL timezone
    - Heavy API by design (FE handles pagination & filters)
    """

    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    now_local = timezone.localtime(now_utc, user_tz)

    try:
        all_orders = (
            DeliveryOrder.objects
            .select_related("pharmacy", "driver")
            .order_by("-created_at")
        )

        result = []

        for order in all_orders:
            # ----------------------------
            # Tracking history
            # ----------------------------
            trackings = (
                OrderTracking.objects
                .filter(order=order)
                .select_related("driver", "pharmacy")
                .order_by("timestamp")
            )

            tracking_history = []
            for t in trackings:
                tracking_history.append({
                    "step": t.step,
                    "performed_by": (
                        t.performed_by
                        or (t.driver.name if t.driver else t.pharmacy.name if t.pharmacy else "Unknown")
                    ),
                    "timestamp_local": timezone.localtime(
                        t.timestamp, user_tz
                    ).isoformat(),
                    "note": t.note or "",
                    "image_url": t.image_url or None
                })

            # ----------------------------
            # Proof images
            # ----------------------------
            proof_images = (
                OrderImage.objects
                .filter(order=order)
                .order_by("uploaded_at")
            )

            images = [{
                "stage": img.stage,
                "image_url": img.image_url,
                "uploaded_at_local": timezone.localtime(
                    img.uploaded_at, user_tz
                ).isoformat()
            } for img in proof_images]

            # ----------------------------
            # Order payload
            # ----------------------------
            result.append({
                "order_id": order.id,
                "status": order.status,
                "rate": float(order.rate),
                "pickup_city": order.pickup_city,
                "drop_city": order.drop_city,
                "pickup_day": order.pickup_day.isoformat(),  # DateField (already local concept)
                "customer_name": order.customer_name,

                "pharmacy": {
                    "id": order.pharmacy.id,
                    "name": order.pharmacy.name,
                    "city": order.pharmacy.city,
                    "email": order.pharmacy.email,
                },

                "driver": (
                    {
                        "id": order.driver.id,
                        "name": order.driver.name,
                        "vehicle_number": order.driver.vehicle_number
                    } if order.driver else None
                ),

                "tracking_history": tracking_history,
                "proof_images": images,

                "created_at_local": timezone.localtime(
                    order.created_at, user_tz
                ).isoformat(),

                "updated_at_local": timezone.localtime(
                    order.updated_at, user_tz
                ).isoformat(),

                "delivered_at_local": (
                    timezone.localtime(order.delivered_at, user_tz).isoformat()
                    if order.delivered_at else None
                ),
            })

        return JsonResponse({
            "success": True,
            "timezone": str(user_tz),
            "orders": result,
            "count": len(result),
            "generated_at_local": now_local.isoformat()
        }, status=200)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)


def _to_local_iso(dt):
    """
    Convert UTC datetime to local timezone ISO string for API response.
    Returns "" if dt is falsy.
    """
    if not dt:
        return ""
    # Ensure aware
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, pytz.UTC)
    return timezone.localtime(dt, settings.USER_TIMEZONE).isoformat()


@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def admin_alerts(request):
    """
    Real-time Admin Alerts (Production)
    - Secure (CSRF + Admin Auth)
    - GET only
    - Uses local timezone boundaries for date-based logic
    - Returns counts + capped samples per alert type
    """

    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    now_local = timezone.localtime(now_utc, user_tz)
    today_local = now_local.date()

    # Limits to keep payload safe
    SAMPLE_LIMIT = 20

    alerts = {
        "operational": [],
        "financial": [],
        "support": []
    }

    # We'll also return counts per alert type (even if samples are capped)
    counts = {
        "operational": {},
        "financial": {},
        "support": {}
    }

    # ----------------------------
    # OPERATIONAL ALERTS
    # ----------------------------

    # A1) Delayed Orders (pickup day passed, still not picked up)
    delayed_qs = DeliveryOrder.objects.filter(
        pickup_day__lt=today_local,
        status__in=["pending", "accepted"]
    )
    counts["operational"]["delayed_orders"] = delayed_qs.count()

    for o in delayed_qs.select_related("pharmacy", "driver").order_by("-updated_at")[:SAMPLE_LIMIT]:
        alerts["operational"].append({
            "alert_key": "delayed_orders",
            "severity": "critical",
            "type": "Delayed Order",
            "message": f"Order #{o.id} pickup day {o.pickup_day} has passed but status is '{o.status}'.",
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "driver_id": o.driver_id,
            "timestamp_local": _to_local_iso(o.updated_at),
        })

    # A2) Unassigned Orders (pending/accepted with no driver)
    unassigned_qs = DeliveryOrder.objects.filter(
        driver__isnull=True,
        status__in=["pending", "accepted"]
    )
    counts["operational"]["unassigned_orders"] = unassigned_qs.count()

    for o in unassigned_qs.select_related("pharmacy").order_by("-created_at")[:SAMPLE_LIMIT]:
        pharmacy_name = o.pharmacy.name if o.pharmacy_id else "Unknown"
        alerts["operational"].append({
            "alert_key": "unassigned_orders",
            "severity": "critical",
            "type": "Unassigned Order",
            "message": f"Order #{o.id} from {pharmacy_name} has no assigned driver.",
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "driver_id": None,
            "timestamp_local": _to_local_iso(o.created_at),
        })

    # A3) Orders stuck too long (status timeout)
    # - inTransit or picked_up older than 2 hours since last update
    two_hours_ago_utc = now_utc - timedelta(hours=2)
    stuck_qs = DeliveryOrder.objects.filter(
        status__in=["inTransit", "picked_up"],
        updated_at__lt=two_hours_ago_utc
    )
    counts["operational"]["stuck_orders"] = stuck_qs.count()

    for o in stuck_qs.select_related("pharmacy", "driver").order_by("updated_at")[:SAMPLE_LIMIT]:
        pharmacy_name = o.pharmacy.name if o.pharmacy_id else "Unknown"
        alerts["operational"].append({
            "alert_key": "stuck_orders",
            "severity": "critical",
            "type": "Stuck Order",
            "message": f"Order #{o.id} by {pharmacy_name} is '{o.status}' for over 2 hours.",
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "driver_id": o.driver_id,
            "timestamp_local": _to_local_iso(o.updated_at),
        })

    # A4) Inactive driver assigned to active orders
    inactive_driver_assigned_qs = DeliveryOrder.objects.filter(
        driver__isnull=False,
        driver__active=False,
        status__in=["pending", "accepted", "inTransit", "picked_up"]
    )
    counts["operational"]["inactive_driver_assigned"] = inactive_driver_assigned_qs.count()

    for o in inactive_driver_assigned_qs.select_related("driver").order_by("-updated_at")[:SAMPLE_LIMIT]:
        driver_name = o.driver.name if o.driver_id else "Unknown"
        alerts["operational"].append({
            "alert_key": "inactive_driver_assigned",
            "severity": "warning",
            "type": "Inactive Driver Assigned",
            "message": f"Inactive driver {driver_name} is assigned to order #{o.id}.",
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "driver_id": o.driver_id,
            "timestamp_local": _to_local_iso(o.updated_at),
        })

    # A5) Delivered orders missing proof (delivered-stage image)
    delivered_missing_proof_qs = DeliveryOrder.objects.filter(status="delivered").annotate(
        has_delivered_image=Exists(
            OrderImage.objects.filter(order_id=OuterRef("id"), stage="delivered")
        )
    ).filter(has_delivered_image=False)

    counts["operational"]["delivered_missing_proof"] = delivered_missing_proof_qs.count()

    for o in delivered_missing_proof_qs.select_related("pharmacy", "driver").order_by("-delivered_at")[:SAMPLE_LIMIT]:
        alerts["operational"].append({
            "alert_key": "delivered_missing_proof",
            "severity": "warning",
            "type": "Missing Delivery Proof",
            "message": f"Order #{o.id} is delivered but has no 'delivered' proof image.",
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "driver_id": o.driver_id,
            "timestamp_local": _to_local_iso(o.delivered_at),
        })

    # A6) Orders with tracking gaps (no tracking entries at all)
    tracking_gap_qs = DeliveryOrder.objects.annotate(
        has_tracking=Exists(
            OrderTracking.objects.filter(order_id=OuterRef("id"))
        )
    ).filter(has_tracking=False)

    counts["operational"]["tracking_gaps"] = tracking_gap_qs.count()

    for o in tracking_gap_qs.select_related("pharmacy", "driver").order_by("-created_at")[:SAMPLE_LIMIT]:
        alerts["operational"].append({
            "alert_key": "tracking_gaps",
            "severity": "warning",
            "type": "Tracking Missing",
            "message": f"Order #{o.id} has no tracking entries logged.",
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "driver_id": o.driver_id,
            "timestamp_local": _to_local_iso(o.created_at),
        })

    # ----------------------------
    # FINANCIAL ALERTS
    # ----------------------------

    # F1) Past-due pharmacy invoices
    past_due_qs = Invoice.objects.filter(status="past_due")
    counts["financial"]["past_due_invoices"] = past_due_qs.count()
    past_due_total = past_due_qs.aggregate(total=Sum("total_amount"))["total"] or 0

    for inv in past_due_qs.select_related("pharmacy").order_by("due_date")[:SAMPLE_LIMIT]:
        pharmacy_name = inv.pharmacy.name if inv.pharmacy_id else "Unknown"
        alerts["financial"].append({
            "alert_key": "past_due_invoices",
            "severity": "critical",
            "type": "Past Due Invoice",
            "message": f"Invoice #{inv.id} for {pharmacy_name} is past due (${float(inv.total_amount):.2f}).",
            "invoice_id": inv.id,
            "pharmacy_id": inv.pharmacy_id,
            "timestamp_local": str(inv.due_date),
        })

    # F2) Unpaid driver invoices
    unpaid_driver_qs = DriverInvoice.objects.filter(
        status="generated",
        due_date__lt=today_local
    )
    counts["financial"]["unpaid_driver_invoices"] = unpaid_driver_qs.count()

    for inv in unpaid_driver_qs.select_related("driver").order_by("due_date")[:SAMPLE_LIMIT]:
        driver_name = inv.driver.name if inv.driver_id else "Unknown"
        alerts["financial"].append({
            "alert_key": "unpaid_driver_invoices",
            "severity": "critical",
            "type": "Unpaid Driver Invoice",
            "message": f"Driver {driver_name}'s invoice #{inv.id} is overdue (${float(inv.total_amount):.2f}).",
            "invoice_id": inv.id,
            "driver_id": inv.driver_id,
            "timestamp_local": str(inv.due_date),
        })

    # F3) Negative net margin (UNCHANGED)
    month_start_local = now_local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if month_start_local.month == 12:
        next_month_start_local = month_start_local.replace(year=month_start_local.year + 1, month=1)
    else:
        next_month_start_local = month_start_local.replace(month=month_start_local.month + 1)

    month_start_utc = month_start_local.astimezone(pytz.UTC)
    next_month_start_utc = next_month_start_local.astimezone(pytz.UTC)

    gross_revenue_mtd = (
        DeliveryOrder.objects.filter(
            status="delivered",
            delivered_at__gte=month_start_utc,
            delivered_at__lt=next_month_start_utc
        ).aggregate(total=Sum("rate"))["total"] or 0
    )

    driver_payout_mtd = (
        DriverInvoice.objects.filter(
            Q(start_date__year=now_local.year, start_date__month=now_local.month) |
            Q(end_date__year=now_local.year, end_date__month=now_local.month)
        ).aggregate(total=Sum("total_amount"))["total"] or 0
    )

    net_margin_mtd = gross_revenue_mtd - driver_payout_mtd
    counts["financial"]["negative_margin"] = 1 if net_margin_mtd < 0 else 0

    if net_margin_mtd < 0:
        alerts["financial"].append({
            "alert_key": "negative_margin",
            "severity": "critical",
            "type": "Negative Net Margin",
            "message": (
                f"Month-to-date net margin is negative. "
                f"Revenue: ${gross_revenue_mtd:.2f}, "
                f"Payouts: ${driver_payout_mtd:.2f}, "
                f"Net: ${net_margin_mtd:.2f}."
            ),
            "timestamp_local": now_local.isoformat(),
        })

    # ------------------------------------------------
    # F4) Revenue leakage — UPDATED TO MATCH INVOICE LOGIC
    # ------------------------------------------------

    revenue_leak_candidates = DeliveryOrder.objects.filter(
        status="delivered",
        delivered_at__isnull=False
    ).select_related("pharmacy")

    revenue_leak_orders = []

    for o in revenue_leak_candidates:
        # Convert delivered_at to LOCAL date
        delivered_local_date = timezone.localtime(
            o.delivered_at,
            user_tz
        ).date()

        # Invoice week logic (EXACTLY SAME AS generator)
        week_start = delivered_local_date
        week_end = week_start + timedelta(days=6)

        # If the week is NOT fully complete yet, skip (no alert)
        if today_local <= week_end:
            continue

        # Check if invoice exists for this exact week
        invoice_exists = Invoice.objects.filter(
            pharmacy_id=o.pharmacy_id,
            start_date=week_start,
            end_date=week_end
        ).exists()

        if not invoice_exists:
            revenue_leak_orders.append(o)

    counts["financial"]["revenue_leakage_orders"] = len(revenue_leak_orders)

    for o in revenue_leak_orders[:SAMPLE_LIMIT]:
        pharmacy_name = o.pharmacy.name if o.pharmacy_id else "Unknown"
        alerts["financial"].append({
            "alert_key": "revenue_leakage_orders",
            "severity": "critical",
            "type": "Missing Invoice (Completed Week)",
            "message": (
                f"Delivered order #{o.id} ({pharmacy_name}) belongs to a completed "
                f"invoice week but no invoice was generated."
            ),
            "order_id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "timestamp_local": _to_local_iso(o.delivered_at),
            "meta": {
                "rate": float(o.rate or 0),
                "week_start": week_start.strftime("%Y-%m-%d"),
                "week_end": week_end.strftime("%Y-%m-%d"),
            },
        })

    # ----------------------------
    # SUPPORT ALERTS
    # ----------------------------

    # S1) Payment-related support tickets (not resolved)
    payment_subjects = ["invoice_payment", "driver_invoice", "order_payment"]
    payment_tickets_qs = ContactAdmin.objects.filter(
        subject__in=payment_subjects
    ).exclude(status="resolved")

    counts["support"]["payment_tickets_open"] = payment_tickets_qs.count()

    for t in payment_tickets_qs.select_related("pharmacy", "driver").order_by("-created_at")[:SAMPLE_LIMIT]:
        sender = t.pharmacy.name if t.pharmacy_id else (t.driver.name if t.driver_id else "Unknown")
        subject_display = t.other_subject if (t.subject == "other" and t.other_subject) else t.get_subject_display()

        alerts["support"].append({
            "alert_key": "payment_tickets_open",
            "severity": "critical",
            "type": "Payment Support Ticket",
            "message": f"Payment-related ticket '{subject_display}' from {sender} is {t.status}.",
            "ticket_id": t.id,
            "timestamp_local": _to_local_iso(t.created_at),
        })

    # S2) Operational support tickets (not resolved)
    ops_subjects = ["pickup_issue", "delivery_delay", "driver_unavailable"]
    ops_tickets_qs = ContactAdmin.objects.filter(
        subject__in=ops_subjects
    ).exclude(status="resolved")

    counts["support"]["operational_tickets_open"] = ops_tickets_qs.count()

    for t in ops_tickets_qs.select_related("pharmacy", "driver").order_by("-created_at")[:SAMPLE_LIMIT]:
        sender = t.pharmacy.name if t.pharmacy_id else (t.driver.name if t.driver_id else "Unknown")
        subject_display = t.other_subject if (t.subject == "other" and t.other_subject) else t.get_subject_display()

        alerts["support"].append({
            "alert_key": "operational_tickets_open",
            "severity": "warning",
            "type": "Operational Support Ticket",
            "message": f"Operational ticket '{subject_display}' from {sender} is {t.status}.",
            "ticket_id": t.id,
            "timestamp_local": _to_local_iso(t.created_at),
        })

    # S3) Repeated complaints pattern (>=3 in last 7 days by same pharmacy or driver)
    seven_days_ago_utc = now_utc - timedelta(days=7)

    # Pharmacy patterns
    pharmacy_pattern = (
        ContactAdmin.objects.filter(created_at__gte=seven_days_ago_utc, pharmacy__isnull=False)
        .values("pharmacy_id")
        .annotate(cnt=Count("id"))
        .filter(cnt__gte=3)
        .order_by("-cnt")
    )
    # Driver patterns
    driver_pattern = (
        ContactAdmin.objects.filter(created_at__gte=seven_days_ago_utc, driver__isnull=False)
        .values("driver_id")
        .annotate(cnt=Count("id"))
        .filter(cnt__gte=3)
        .order_by("-cnt")
    )

    counts["support"]["repeat_complaints_pharmacy"] = pharmacy_pattern.count()
    counts["support"]["repeat_complaints_driver"] = driver_pattern.count()

    # Sample a few pattern alerts (top offenders)
    for row in pharmacy_pattern[:10]:
        alerts["support"].append({
            "alert_key": "repeat_complaints_pharmacy",
            "severity": "warning",
            "type": "Repeated Complaints",
            "message": f"Pharmacy ID {row['pharmacy_id']} has {row['cnt']} support tickets in the last 7 days.",
            "pharmacy_id": row["pharmacy_id"],
            "timestamp_local": now_local.isoformat(),
        })

    for row in driver_pattern[:10]:
        alerts["support"].append({
            "alert_key": "repeat_complaints_driver",
            "severity": "warning",
            "type": "Repeated Complaints",
            "message": f"Driver ID {row['driver_id']} has {row['cnt']} support tickets in the last 7 days.",
            "driver_id": row["driver_id"],
            "timestamp_local": now_local.isoformat(),
        })

    # ----------------------------
    # RESPONSE
    # ----------------------------
    category_counts = {k: len(v) for k, v in alerts.items()}
    total_alerts_sampled = sum(category_counts.values())

    # Also compute total counts per category (sum of per-type counts)
    totals_by_category = {
        "operational": int(sum(counts["operational"].values())),
        "financial": int(sum(counts["financial"].values())),
        "support": int(sum(counts["support"].values())),
    }
    total_alerts_total = sum(totals_by_category.values())

    return JsonResponse(
        {
            "success": True,
            "timezone": str(user_tz),
            "generated_at_local": now_local.isoformat(),
            "summary": {
                "total_alerts": total_alerts_total,              # total matches in DB (real-time)
                "total_alerts_sampled": total_alerts_sampled,    # items included in response lists
                "totals_by_category": totals_by_category,
                "sample_counts_by_category": category_counts,
                "counts_by_type": counts,
                "financial_totals": {
                    "past_due_amount_total": float(past_due_total),
                    "revenue_mtd": float(gross_revenue_mtd),
                    "payouts_mtd": float(driver_payout_mtd),
                    "net_margin_mtd": float(net_margin_mtd),
                }
            },
            "alerts": {
                "operational": alerts["operational"],
                "financial": alerts["financial"],
                "support": alerts["support"],
            }
        },
        status=200
    )




from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from django.db.models import Sum
from datetime import datetime
import pytz

# Prod helper: consistent local timezone formatting
def _to_local_iso(dt):
    if not dt:
        return None
    return timezone.localtime(dt, settings.USER_TIMEZONE).isoformat()

@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def admin_order_list(request):
    """
    PRODUCTION: Admin Order List (heavy, FE does pagination/filtering)
    - Secure (CSRF + Admin Auth)
    - GET only
    - Returns all datetime fields in settings.USER_TIMEZONE
    - Includes ID/Signature requirements + verification fields + driver identity_url + signature_ack_url
    """
    try:
        user_tz = settings.USER_TIMEZONE

        # Keep your approach (values + per-order queries), but add missing fields
        orders = list(
            DeliveryOrder.objects.all()
            .order_by("pickup_day")
            .values(
                "id",
                "pharmacy_id",
                "driver_id",
                "pickup_address",
                "pickup_city",
                "pickup_day",
                "drop_address",
                "drop_city",
                "status",
                "rate",
                "customer_name",
                "customer_phone",
                "alternate_contact",
                "delivery_notes",
                "driver_notes",

                # ✅ Missing business fields
                "signature_required",
                "id_verification_required",
                "id_verified",
                "signature_ack_url",
                "is_delivered",
                "delivered_at",

                "created_at",
                "updated_at",
            )
        )

        result = []

        for order in orders:
            order_id = order["id"]

            # -----------------------
            # Pharmacy info
            # -----------------------
            pharmacy_info = None
            if order.get("pharmacy_id"):
                try:
                    p = Pharmacy.objects.filter(id=order["pharmacy_id"]).values(
                        "id", "name", "email", "phone_number",
                        "city", "province", "postal_code", "country",
                        "active", "created_at"
                    ).first()
                    if p:
                        pharmacy_info = {
                            "id": p["id"],
                            "name": p["name"],
                            "email": p["email"],
                            "phone_number": p["phone_number"],
                            "city": p["city"],
                            "province": p["province"],
                            "postal_code": p["postal_code"],
                            "country": p["country"],
                            "active": p["active"],
                            "created_at_local": _to_local_iso(p["created_at"]),
                        }
                except:
                    pass

            # -----------------------
            # Driver info (include identity_url)
            # -----------------------
            driver_info = None
            if order.get("driver_id"):
                try:
                    d = Driver.objects.filter(id=order["driver_id"]).values(
                        "id", "name", "email", "phone_number",
                        "vehicle_number", "active", "created_at",
                        "identity_url"
                    ).first()
                    if d:
                        driver_info = {
                            "id": d["id"],
                            "name": d["name"],
                            "email": d["email"],
                            "phone_number": d["phone_number"],
                            "vehicle_number": d["vehicle_number"],
                            "active": d["active"],
                            "identity_url": d.get("identity_url"),
                            "has_identity_uploaded": bool(d.get("identity_url")),
                            "created_at_local": _to_local_iso(d["created_at"]),
                        }
                except:
                    pass

            # -----------------------
            # Tracking history (local time)
            # -----------------------
            tracking_info = []
            try:
                tracks = (
                    OrderTracking.objects
                    .filter(order_id=order_id)
                    .order_by("timestamp")
                    .values("step", "performed_by", "timestamp", "note", "image_url")
                )
                for t in tracks:
                    tracking_info.append({
                        "step": t["step"],
                        "performed_by": t["performed_by"] or "",
                        "timestamp_local": _to_local_iso(t["timestamp"]),
                        "note": t["note"] or "",
                        "image_url": t["image_url"] or None,
                    })
            except:
                pass

            # -----------------------
            # Proof images (local time)
            # -----------------------
            proof_images = []
            try:
                imgs = (
                    OrderImage.objects
                    .filter(order_id=order_id)
                    .order_by("uploaded_at")
                    .values("stage", "image_url", "uploaded_at")
                )
                for img in imgs:
                    proof_images.append({
                        "stage": img["stage"],
                        "image_url": img["image_url"],
                        "uploaded_at_local": _to_local_iso(img["uploaded_at"]),
                    })
            except:
                pass

            # -----------------------
            # Commission info (same logic)
            # -----------------------
            rate = float(order["rate"]) if order["rate"] else 0.0
            commission = round(rate * settings.DRIVER_COMMISSION_RATE, 2)
            net = round(rate - commission, 2)

            # -----------------------
            # Build response item (add missing business fields)
            # -----------------------
            result.append({
                "order_id": order_id,
                "pharmacy": pharmacy_info,
                "driver": driver_info,

                "pickup_address": order.get("pickup_address") or "",
                "pickup_city": order.get("pickup_city") or "",
                "pickup_day": str(order.get("pickup_day") or ""),

                "drop_address": order.get("drop_address") or "",
                "drop_city": order.get("drop_city") or "",

                "status": order.get("status") or "",
                "amount": rate,

                "customer_name": order.get("customer_name") or "",
                "customer_phone": order.get("customer_phone") or "",
                "alternate_contact": order.get("alternate_contact") or "",
                "delivery_notes": order.get("delivery_notes") or "",
                "driver_notes" : order.get("driver_notes") or "",

                # ✅ ID + signature requirements / verification
                "signature_required": bool(order.get("signature_required")),
                "id_verification_required": bool(order.get("id_verification_required")),
                "id_verified": bool(order.get("id_verified")),
                "signature_ack_url": order.get("signature_ack_url") or None,

                # ✅ delivery completion fields
                "is_delivered": bool(order.get("is_delivered")),
                "delivered_at_local": _to_local_iso(order.get("delivered_at")),

                "created_at_local": _to_local_iso(order.get("created_at")),
                "updated_at_local": _to_local_iso(order.get("updated_at")),

                "tracking_history": tracking_info,
                "proof_images": proof_images,

                "commission_info": {
                    "commission_rate": f"{int(settings.DRIVER_COMMISSION_RATE * 100)}%",
                    "commission_decimal": settings.DRIVER_COMMISSION_RATE,
                    "commission_amount": commission,
                    "net_payout_driver": net
                }
            })

        return JsonResponse({
            "success": True,
            "timezone": str(user_tz),
            "generated_at_local": _to_local_iso(timezone.now()),
            "total_orders": len(result),
            "orders": result
        }, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)


# @csrf_exempt
# def delivery_rates_list(request):
#     """
#     GET /api/deliveryRates/ -> returns all delivery distance rates.
#     """
#     if request.method != "GET":
#         return JsonResponse({"success": False, "error": "Only GET allowed"}, status=405)

#     try:
#         from .models import DeliveryDistanceRate
        
#         rates = DeliveryDistanceRate.objects.all().order_by("min_distance_km")
        
#         data = []
#         for r in rates:
#             try:
#                 min_km = float(r.min_distance_km) if r.min_distance_km else 0.0
#             except:
#                 min_km = 0.0
            
#             try:
#                 max_km = float(r.max_distance_km) if r.max_distance_km else None
#             except:
#                 max_km = None
            
#             try:
#                 rate_val = float(r.rate) if r.rate else 0.0
#             except:
#                 rate_val = 0.0
            
#             # Build label
#             if max_km:
#                 label = f"{min_km}-{max_km} km = ${rate_val}"
#             else:
#                 label = f"{min_km}+ km = ${rate_val}"
            
#             data.append({
#                 "id": r.id,
#                 "min_distance_km": min_km,
#                 "max_distance_km": max_km,
#                 "rate": rate_val,
#                 "label": label
#             })

#         return JsonResponse({
#             "success": True,
#             "count": len(data),
#             "rates": data
#         }, status=200)

#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         return JsonResponse({
#             "success": False,
#             "error": str(e),
#             "error_type": type(e).__name__
#         }, status=500)


@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def delivery_rates_list(request):
    """
    PRODUCTION: Delivery Rates List

    GET /api/deliveryRates/

    - Secure (CSRF protected)
    - GET only
    - Returns all delivery distance slabs
    - Uses UTC for DB, local timezone for metadata
    """

    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    now_local = timezone.localtime(now_utc, user_tz)

    try:
        rates = DeliveryDistanceRate.objects.all().order_by("min_distance_km")

        data = []
        for r in rates:
            min_km = float(r.min_distance_km or 0)
            max_km = float(r.max_distance_km) if r.max_distance_km is not None else None
            rate_val = float(r.rate or 0)

            # Human-friendly label
            if max_km is not None:
                label = f"{min_km}-{max_km} km = ${rate_val}"
            else:
                label = f"{min_km}+ km = ${rate_val}"

            data.append({
                "id": r.id,
                "min_distance_km": min_km,
                "max_distance_km": max_km,
                "rate": rate_val,
                "label": label
            })

        return JsonResponse({
            "success": True,
            "count": len(data),
            "rates": data,
            "timezone": str(user_tz),
            "generated_at_local": now_local.isoformat()
        }, status=200)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "timezone": str(user_tz),
            "generated_at_local": now_local.isoformat()
        }, status=500)


@csrf_protect
@admin_auth_required
@require_http_methods(["PUT"])
def edit_order(request, order_id):
    """
    PRODUCTION: Admin Edit Order
    PUT /api/editOrder/<order_id>/
    
    - Secure (CSRF + Admin Auth)
    - PUT only
    - Validates order status before driver reassignment
    - Creates audit trail in OrderTracking for driver changes AND status changes
    - Returns timestamps in settings.USER_TIMEZONE
    - Stores data in UTC
    
    Editable fields:
      Core Delivery:
        - pickup_address, pickup_city, pickup_day
        - drop_address, drop_city
      
      Customer Info:
        - customer_name, customer_phone, alternate_contact
      
      Delivery Instructions:
        - delivery_notes, signature_required, id_verification_required
      
      Financial:
        - rate
      
      Status & Assignment:
        - status (with audit trail)
        - driver_id (with status validation and audit trail)
    """
    
    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    
    # Parse request body
    try:
        body = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse({
            "success": False, 
            "error": "Invalid JSON body"
        }, status=400)
    
    # Validate order exists
    try:
        order = DeliveryOrder.objects.select_related('pharmacy', 'driver').get(id=order_id)
    except DeliveryOrder.DoesNotExist:
        return JsonResponse({
            "success": False, 
            "error": f"Order #{order_id} not found"
        }, status=404)
    
    # Track the original status before any changes
    original_status = order.status
    
    # Define editable fields
    editable_fields = [
        # Core delivery details
        "pickup_address",
        "pickup_city", 
        "pickup_day",
        "drop_address",
        "drop_city",
        
        # Customer info
        "customer_name",
        "customer_phone",
        "alternate_contact",
        
        # Delivery instructions
        "delivery_notes",
        "signature_required",
        "id_verification_required",
        
        # Financial
        "rate",
        
        # Status
        "status",
    ]
    
    # Track changes for response
    changes_made = []
    
    # Track if status was changed
    status_changed = False
    new_status = None
    
    # Special handling for driver_id (not in regular editable_fields)
    driver_reassignment_note = None
    if "driver_id" in body:
        # Validate status allows driver reassignment
        prohibited_statuses = ['picked_up', 'inTransit', 'delivered', 'cancelled']
        if order.status in prohibited_statuses:
            return JsonResponse({
                "success": False,
                "error": f"Cannot reassign driver when order status is '{order.status}'. Driver reassignment only allowed for 'pending' or 'accepted' orders."
            }, status=400)
        
        # Validate new driver exists and is active
        new_driver_id = body["driver_id"]
        
        # Allow null to unassign driver
        if new_driver_id is None:
            old_driver_name = order.driver.name if order.driver else "Unassigned"
            order.driver = None
            driver_reassignment_note = f"Driver unassigned (was: {old_driver_name})"
            changes_made.append("driver_id (unassigned)")
        else:
            try:
                new_driver = Driver.objects.get(id=new_driver_id, active=True)
            except Driver.DoesNotExist:
                return JsonResponse({
                    "success": False,
                    "error": f"Driver #{new_driver_id} not found or inactive"
                }, status=404)
            
            # Store old driver for audit trail
            old_driver = order.driver
            old_driver_name = old_driver.name if old_driver else "Unassigned"
            
            # Update driver
            order.driver = new_driver
            driver_reassignment_note = f"Driver reassigned from {old_driver_name} to {new_driver.name}"
            changes_made.append(f"driver_id ({old_driver_name} → {new_driver.name})")
    
    # Apply updates for regular editable fields
    for field in editable_fields:
        if field in body:
            old_value = getattr(order, field, None)
            new_value = body[field]
            
            # Skip if no change
            if old_value == new_value:
                continue
            
            try:
                # Type-specific parsing
                if field == "pickup_day":
                    parsed_date = parse_date(str(new_value))
                    if not parsed_date:
                        raise ValueError("Invalid date format")
                    order.pickup_day = parsed_date
                    changes_made.append(f"pickup_day ({old_value} → {new_value})")
                
                elif field == "rate":
                    order.rate = float(new_value)
                    changes_made.append(f"rate (${old_value} → ${new_value})")
                
                elif field in ["signature_required", "id_verification_required"]:
                    order.__dict__[field] = bool(new_value)
                    changes_made.append(f"{field} ({old_value} → {new_value})")
                
                elif field == "status":
                    # Track status change
                    if old_value != new_value:
                        status_changed = True
                        new_status = new_value
                    setattr(order, field, new_value)
                    changes_made.append(f"status ({old_value} → {new_value})")
                
                else:
                    setattr(order, field, new_value)
                    changes_made.append(field)
            
            except (ValueError, TypeError) as e:
                return JsonResponse({
                    "success": False,
                    "error": f"Invalid value for '{field}': {str(e)}"
                }, status=400)
    
    # Validate: at least one field was updated
    if not changes_made:
        return JsonResponse({
            "success": False,
            "error": "No changes provided"
        }, status=400)
    
    # Save order (triggers updated_at)
    try:
        order.save()
    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": f"Failed to save order: {str(e)}"
        }, status=500)
    
    # Create audit trail for driver reassignment
    if driver_reassignment_note:
        try:
            OrderTracking.objects.create(
                order=order,
                driver=order.driver,  # New driver (or None)
                pharmacy=order.pharmacy,
                step=order.status,
                performed_by='Admin',
                timestamp=now_utc,  # Store in UTC
                note=driver_reassignment_note
            )
        except Exception as e:
            # Log error but don't fail the request
            print(f"Warning: Failed to create tracking entry for driver change: {str(e)}")
    
    # Create audit trail for status change
    if status_changed:
        try:
            OrderTracking.objects.create(
                order=order,
                driver=order.driver,
                pharmacy=order.pharmacy,
                step=new_status,
                performed_by='Admin',
                timestamp=now_utc,  # Store in UTC
                note=f"Status changed from '{original_status}' to '{new_status}' by Admin"
            )
        except Exception as e:
            # Log error but don't fail the request
            print(f"Warning: Failed to create tracking entry for status change: {str(e)}")
    
    # Build response with local timezone
    updated_data = {
        "order_id": order.id,
        
        # Core delivery
        "pickup_address": order.pickup_address,
        "pickup_city": order.pickup_city,
        "pickup_day": str(order.pickup_day),
        "drop_address": order.drop_address,
        "drop_city": order.drop_city,
        
        # Customer info
        "customer_name": order.customer_name,
        "customer_phone": order.customer_phone,
        "alternate_contact": order.alternate_contact or "",
        
        # Delivery instructions
        "delivery_notes": order.delivery_notes or "",
        "signature_required": order.signature_required,
        "id_verification_required": order.id_verification_required,
        
        # Financial
        "rate": float(order.rate),
        
        # Status
        "status": order.status,
        
        # Driver info
        "driver": {
            "id": order.driver.id,
            "name": order.driver.name,
            "email": order.driver.email,
        } if order.driver else None,
        
        # Timestamps (local timezone)
        "updated_at_local": _to_local_iso(order.updated_at),
        "created_at_local": _to_local_iso(order.created_at),
    }
    
    return JsonResponse({
        "success": True,
        "message": f"Order #{order_id} updated successfully",
        "changes": changes_made,
        "order": updated_data,
        "timezone": str(user_tz),
        "updated_at_server_local": _to_local_iso(now_utc)
    }, status=200)


@csrf_protect
@admin_auth_required
@require_http_methods(["DELETE", "POST"])
def cancel_order(request, order_id: int):
    """
    PRODUCTION: Cancel Order (Admin Only with Status Restrictions)
    
    DELETE/POST /api/orders/{order_id}/cancel/
    
    - Secure (CSRF + Admin Auth)
    - DELETE or POST methods
    - Status-based cancellation restrictions:
      * pending: ✅ Allowed (no cost incurred)
      * accepted: ✅ Allowed with logging (driver not started)
      * picked_up: ⚠️ Controlled/Rare (chain of custody concerns)
      * inTransit: ❌ Not allowed (operational + legal risk)
      * delivered: ❌ Never allowed (financial + audit integrity)
      * cancelled: 🚫 Already cancelled (terminal state)
    - Soft delete by setting status='cancelled'
    - Creates OrderTracking entry for audit trail
    - Sends email notifications to pharmacy and driver
    - Returns timestamps in settings.USER_TIMEZONE
    - Stores data in UTC
    """
    
    # Get user timezone from settings
    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    now_local = timezone.localtime(now_utc, user_tz)
    
    # Validate order exists
    try:
        order = DeliveryOrder.objects.select_related('pharmacy', 'driver').get(id=order_id)
    except DeliveryOrder.DoesNotExist:
        return JsonResponse({
            "success": False, 
            "error": "Order not found."
        }, status=404)

    prev_status = order.status

    # ============================================
    # STATUS-BASED CANCELLATION RESTRICTIONS
    # ============================================
    
    # ❌ Never allow cancellation of delivered orders (financial + audit integrity)
    if prev_status == "delivered":
        return JsonResponse({
            "success": False,
            "error": "Delivered orders cannot be cancelled due to financial and audit integrity requirements."
        }, status=400)
    
    # 🚫 Already cancelled (terminal state)
    if prev_status == "cancelled":
        return JsonResponse({
            "success": False,
            "error": "Order is already cancelled."
        }, status=400)
    
    # ❌ Not allowed for inTransit orders (operational + legal risk)
    if prev_status == "inTransit":
        return JsonResponse({
            "success": False,
            "error": "Orders in transit cannot be cancelled due to operational and legal risks. Please wait for delivery or contact operations."
        }, status=400)
    
    # ⚠️ Controlled/Rare for picked_up orders (chain of custody concerns)
    if prev_status == "picked_up":
        return JsonResponse({
            "success": False,
            "error": "Orders that have been picked up cannot be cancelled due to chain of custody concerns. Please contact operations if cancellation is critical."
        }, status=400)
    
    # ✅ Allowed for pending (no cost incurred)
    # ✅ Allowed for accepted (driver not started, logged for audit)
    
    # Additional logging for accepted orders
    if prev_status == "accepted":
        print(f"[AUDIT] Admin cancelled accepted order #{order.id} - Driver: {order.driver.name if order.driver else 'None'}")

    # Update order status and timestamp (store in UTC)
    order.status = "cancelled"
    order.updated_at = now_utc
    order.save(update_fields=["status", "updated_at"])

    # Always add tracking entry (timestamp in UTC)
    OrderTracking.objects.create(
        order=order,
        driver=order.driver,
        pharmacy=order.pharmacy,
        step="cancelled",
        performed_by="admin_panel",
        note=f"Order cancelled via Admin Dashboard. Previous status: {prev_status}",
        timestamp=now_utc,
    )

    # ---- Send cancellation email to pharmacy ----
    if order.pharmacy and order.pharmacy.email:
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            logo_url = settings.LOGO_URL
            
            # Use local timezone for display
            now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y") if order.pickup_day else "N/A"

            pharmacy_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Cancelled • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:#dc2626;padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}" alt="{settings.COMPANY_OPERATING_NAME}" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#ffffff;">
                      Order Cancelled
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            
            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Order #{order.id} has been cancelled
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{order.pharmacy.name}</strong>, we're writing to inform you that delivery order <strong>#{order.id}</strong> has been cancelled through the admin dashboard.
                </p>
                
                <div style="margin:18px 0;background:#fef2f2;border:1px solid #ef4444;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#991b1b;">
                    ✕ Order Status: <strong>Cancelled</strong> — No further action required
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📦 Order Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Order ID:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{order.id}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Customer:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.customer_name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivery Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        ${order.rate}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Scheduled Pickup:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pickup_date_str}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Previous Status:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {prev_status.replace('_', ' ').title()}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Cancelled At:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {now_str}
                      </td>
                    </tr>
                  </table>
                </div>
                
                <div style="margin:18px 0;background:#fff7ed;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏠 Delivery Details
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    Customer: {order.customer_name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_city}
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#fef3c7;border-left:3px solid #f59e0b;border-radius:8px;padding:14px 16px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#92400e;">
                    ℹ️ If you have questions about this cancellation, please contact our support team.
                  </p>
                </div>
                
                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For questions or concerns, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>
            
            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for using {settings.COMPANY_OPERATING_NAME}.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            pharmacy_text = (
                f"Order Cancelled - {settings.COMPANY_OPERATING_NAME}\n\n"
                f"Hello {order.pharmacy.name},\n\n"
                f"Delivery order #{order.id} has been cancelled through the admin dashboard.\n\n"
                f"ORDER DETAILS:\n"
                f"- Order ID: #{order.id}\n"
                f"- Customer: {order.customer_name}\n"
                f"- Delivery Rate: ${order.rate}\n"
                f"- Scheduled Pickup: {pickup_date_str}\n"
                f"- Previous Status: {prev_status.replace('_', ' ').title()}\n"
                f"- Cancelled At: {now_str}\n\n"
                f"DELIVERY DETAILS:\n"
                f"Customer: {order.customer_name}\n"
                f"{order.drop_address}\n"
                f"{order.drop_city}\n\n"
                f"If you have questions about this cancellation, please contact support at {settings.EMAIL_ADMIN_OFFICE}\n"
            )

            _send_html_email_operations(
                subject=f"Order #{order.id} Cancelled • {settings.COMPANY_OPERATING_NAME}",
                to_email=order.pharmacy.email,
                html=pharmacy_html,
                text_fallback=pharmacy_text,
            )
            
        except Exception as e:
            print(f"ERROR sending pharmacy cancellation email: {str(e)}")
            import traceback
            traceback.print_exc()

    # ---- Send cancellation email to driver (if assigned) ----
    if order.driver and order.driver.email:
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            logo_url = settings.LOGO_URL
            
            # Use local timezone for display
            now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y") if order.pickup_day else "N/A"

            driver_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Cancelled • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:#dc2626;padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}" alt="{settings.COMPANY_OPERATING_NAME}" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#ffffff;">
                      Order Cancelled
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            
            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Delivery order #{order.id} cancelled
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hello <strong>{order.driver.name}</strong>, the delivery order <strong>#{order.id}</strong> that was assigned to you has been cancelled through the admin dashboard. No further action is required from you.
                </p>
                
                <div style="margin:18px 0;background:#fef2f2;border:1px solid #ef4444;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#991b1b;">
                    ✕ Order Status: <strong>Cancelled</strong> — No delivery needed
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📦 Order Information
                  </p>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Order ID:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        #{order.id}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Pharmacy:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.pharmacy.name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Customer:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {order.customer_name}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Delivery Rate:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        ${order.rate}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Scheduled Pickup:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {pickup_date_str}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Previous Status:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {prev_status.replace('_', ' ').title()}
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:4px 0;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        Cancelled At:
                      </td>
                      <td style="padding:4px 0;font:400 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        {now_str}
                      </td>
                    </tr>
                  </table>
                </div>
                
                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    📍 Pickup Location
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    {order.pharmacy.name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.pickup_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.pickup_city}
                  </p>
                </div>
                
                <div style="margin:18px 0;background:#fff7ed;border:1px solid {brand_accent};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 12px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    🏠 Delivery Destination
                  </p>
                  <p style="margin:0 0 4px;font:600 13px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    Customer: {order.customer_name}
                  </p>
                  <p style="margin:0 0 2px;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_address}
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    {order.drop_city}
                  </p>
                </div>
                
                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For questions or concerns, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>
            
            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for being part of the {settings.COMPANY_OPERATING_NAME} team.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            driver_text = (
                f"Order Cancelled - {settings.COMPANY_OPERATING_NAME}\n\n"
                f"Hello {order.driver.name},\n\n"
                f"The delivery order #{order.id} that was assigned to you has been cancelled. No delivery is needed.\n\n"
                f"ORDER DETAILS:\n"
                f"- Order ID: #{order.id}\n"
                f"- Pharmacy: {order.pharmacy.name}\n"
                f"- Customer: {order.customer_name}\n"
                f"- Delivery Rate: ${order.rate}\n"
                f"- Scheduled Pickup: {pickup_date_str}\n"
                f"- Previous Status: {prev_status.replace('_', ' ').title()}\n"
                f"- Cancelled At: {now_str}\n\n"
                f"PICKUP LOCATION:\n"
                f"{order.pharmacy.name}\n"
                f"{order.pickup_address}\n"
                f"{order.pickup_city}\n\n"
                f"DELIVERY DESTINATION:\n"
                f"Customer: {order.customer_name}\n"
                f"{order.drop_address}\n"
                f"{order.drop_city}\n\n"
                f"For questions, contact operations at {settings.EMAIL_OPERATIONS}\n"
            )

            _send_html_email_operations(
                subject=f"Order #{order.id} Cancelled • {settings.COMPANY_OPERATING_NAME}",
                to_email=order.driver.email,
                html=driver_html,
                text_fallback=driver_text,
            )
            
        except Exception as e:
            print(f"ERROR sending driver cancellation email: {str(e)}")
            import traceback
            traceback.print_exc()

    # Return response with local timezone
    return JsonResponse({
        "success": True,
        "message": f"Order #{order.id} successfully cancelled.",
        "order_id": order.id,
        "previous_status": prev_status,
        "new_status": "cancelled",
        "updated_at_local": timezone.localtime(order.updated_at, user_tz).isoformat(),
        "cancelled_at_local": now_local.isoformat(),
        "timezone": str(user_tz),
    }, status=200)

@csrf_protect
@require_http_methods(["POST"])
@admin_auth_required
def add_delivery_rate(request):
    """
    Admin API to create a new DeliveryDistanceRate slab.

    Expected JSON body:
    {
      "min_distance_km": number (required, >= 0),
      "max_distance_km": number|null (optional, >= min_distance_km),
      "rate": number (required, >= 0)
    }
    """

    # -------------------------------
    # Parse JSON
    # -------------------------------
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({
            "success": False,
            "code": "INVALID_JSON",
            "message": "Invalid JSON body."
        }, status=400)

    min_km = payload.get("min_distance_km")
    max_km = payload.get("max_distance_km")
    rate = payload.get("rate")

    # -------------------------------
    # Validation
    # -------------------------------
    try:
        if min_km is None:
            return JsonResponse({
                "success": False,
                "code": "MIN_DISTANCE_REQUIRED",
                "message": "min_distance_km is required."
            }, status=400)

        if rate is None:
            return JsonResponse({
                "success": False,
                "code": "RATE_REQUIRED",
                "message": "rate is required."
            }, status=400)

        min_km = Decimal(str(min_km))
        rate = Decimal(str(rate))

        if min_km < 0:
            return JsonResponse({
                "success": False,
                "code": "INVALID_MIN_DISTANCE",
                "message": "min_distance_km must be >= 0."
            }, status=400)

        if rate < 0:
            return JsonResponse({
                "success": False,
                "code": "INVALID_RATE",
                "message": "rate must be >= 0."
            }, status=400)

        if max_km is not None:
            max_km = Decimal(str(max_km))
            if max_km < min_km:
                return JsonResponse({
                    "success": False,
                    "code": "INVALID_MAX_DISTANCE",
                    "message": "max_distance_km must be >= min_distance_km."
                }, status=400)
        else:
            max_km = None

    except InvalidOperation:
        return JsonResponse({
            "success": False,
            "code": "INVALID_NUMBER",
            "message": "Distances and rate must be valid numbers."
        }, status=400)

    # -------------------------------
    # Atomic creation + overlap guard
    # -------------------------------
    try:
        with transaction.atomic():
            existing_rates = DeliveryDistanceRate.objects.select_for_update()

            for r in existing_rates:
                r_min = r.min_distance_km
                r_max = r.max_distance_km  # may be None

                # overlap condition
                if (
                    (max_km is None or r_min <= max_km)
                    and (r_max is None or r_max >= min_km)
                ):
                    return JsonResponse({
                        "success": False,
                        "code": "OVERLAPPING_RANGE",
                        "message": (
                            f"Range {min_km}–{max_km if max_km is not None else '∞'} "
                            f"overlaps existing range {r_min}–{r_max if r_max is not None else '∞'}."
                        )
                    }, status=409)

            new_rate = DeliveryDistanceRate.objects.create(
                min_distance_km=min_km,
                max_distance_km=max_km,
                rate=rate,
            )

            # Optional audit log
            # logger.info(
            #     f"Admin {request.admin.id} added delivery rate "
            #     f"{min_km}-{max_km or '∞'} @ {rate}"
            # )

        return JsonResponse({
            "success": True,
            "message": "Delivery rate added successfully.",
            "rate": {
                "id": new_rate.id,
                "min_distance_km": float(new_rate.min_distance_km),
                "max_distance_km": (
                    float(new_rate.max_distance_km)
                    if new_rate.max_distance_km is not None else None
                ),
                "rate": float(new_rate.rate),
            }
        }, status=201)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "code": "SERVER_ERROR",
            "message": str(e)
        }, status=500)


# # ✏️ EDIT DELIVERY RATE
# @csrf_exempt
# @require_http_methods(["PUT", "POST"])  # Allow both PUT and POST for compatibility
# def edit_delivery_rate(request, rate_id):
#     """
#     Edit an existing DeliveryDistanceRate entry.
#     URL: /api/deliveryRates/<id>/edit/
    
#     Expected JSON body:
#     {
#       "min_distance_km": number (optional, >= 0),
#       "max_distance_km": number|null (optional, >= min_distance_km),
#       "rate": number (optional, >= 0)
#     }
#     """
#     try:
#         # Parse request body
#         try:
#             payload = json.loads(request.body.decode("utf-8"))
#         except json.JSONDecodeError:
#             return JsonResponse(
#                 {"success": False, "error": "Invalid JSON payload."},
#                 status=400
#             )

#         # Check if rate exists
#         try:
#             rate_obj = DeliveryDistanceRate.objects.get(id=rate_id)
#         except DeliveryDistanceRate.DoesNotExist:
#             return JsonResponse(
#                 {"success": False, "error": f"Rate with ID {rate_id} not found."},
#                 status=404
#             )

#         # Extract fields
#         min_km = payload.get("min_distance_km")
#         max_km = payload.get("max_distance_km")
#         rate = payload.get("rate")

#         # Track if any changes were made
#         changes_made = False

#         # Update min_distance_km
#         if min_km is not None:
#             try:
#                 min_val = Decimal(str(min_km))
#                 if min_val < 0:
#                     return JsonResponse(
#                         {"success": False, "error": "min_distance_km must be >= 0."},
#                         status=400
#                     )
#                 rate_obj.min_distance_km = min_val
#                 changes_made = True
#             except (InvalidOperation, ValueError):
#                 return JsonResponse(
#                     {"success": False, "error": "Invalid min_distance_km value."},
#                     status=400
#                 )

#         # Update max_distance_km
#         if max_km is not None:
#             if max_km == "" or max_km == "null":
#                 rate_obj.max_distance_km = None
#                 changes_made = True
#             else:
#                 try:
#                     max_val = Decimal(str(max_km))
#                     if max_val < rate_obj.min_distance_km:
#                         return JsonResponse(
#                             {"success": False, "error": "max_distance_km must be >= min_distance_km."},
#                             status=400
#                         )
#                     rate_obj.max_distance_km = max_val
#                     changes_made = True
#                 except (InvalidOperation, ValueError):
#                     return JsonResponse(
#                         {"success": False, "error": "Invalid max_distance_km value."},
#                         status=400
#                     )

#         # Update rate
#         if rate is not None:
#             try:
#                 rate_val = Decimal(str(rate))
#                 if rate_val < 0:
#                     return JsonResponse(
#                         {"success": False, "error": "rate must be >= 0."},
#                         status=400
#                     )
#                 rate_obj.rate = rate_val
#                 changes_made = True
#             except (InvalidOperation, ValueError):
#                 return JsonResponse(
#                     {"success": False, "error": "Invalid rate value."},
#                     status=400
#                 )

#         if not changes_made:
#             return JsonResponse(
#                 {"success": False, "message": "No fields were updated."},
#                 status=400
#             )

#         # Save changes
#         rate_obj.save()

#         # Build response
#         response_data = {
#             "success": True,
#             "message": "Delivery rate updated successfully.",
#             "rate": {
#                 "id": rate_obj.id,
#                 "min_distance_km": float(rate_obj.min_distance_km) if rate_obj.min_distance_km else 0.0,
#                 "max_distance_km": float(rate_obj.max_distance_km) if rate_obj.max_distance_km else None,
#                 "rate": float(rate_obj.rate) if rate_obj.rate else 0.0,
#             },
#         }

#         return JsonResponse(response_data, status=200)

#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         return JsonResponse({
#             "success": False,
#             "error": f"Internal server error: {str(e)}",
#             "error_type": type(e).__name__
#         }, status=500)


@csrf_protect
@admin_auth_required
@require_http_methods(["PUT", "POST"])  # PUT preferred, POST allowed for compatibility
def edit_delivery_rate(request, rate_id):
    """
    PRODUCTION: Edit an existing DeliveryDistanceRate entry.

    URL:
      PUT /api/deliveryRates/<id>/edit/

    Expected JSON body (all fields optional):
    {
      "min_distance_km": number (>= 0),
      "max_distance_km": number | null (>= min_distance_km),
      "rate": number (>= 0)
    }

    Notes:
    - Partial updates supported
    - No time-based logic (pricing config)
    - Does NOT affect historical orders
    """

    # -----------------------------
    # Parse JSON body
    # -----------------------------
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON payload."},
            status=400
        )

    # -----------------------------
    # Validate rate exists
    # -----------------------------
    try:
        rate_obj = DeliveryDistanceRate.objects.get(id=rate_id)
    except DeliveryDistanceRate.DoesNotExist:
        return JsonResponse(
            {"success": False, "error": f"Rate with ID {rate_id} not found."},
            status=404
        )

    # -----------------------------
    # Extract fields
    # -----------------------------
    min_km = payload.get("min_distance_km")
    max_km = payload.get("max_distance_km")
    rate = payload.get("rate")

    changes_made = False

    # -----------------------------
    # Update min_distance_km
    # -----------------------------
    if min_km is not None:
        try:
            min_val = Decimal(str(min_km))
            if min_val < 0:
                return JsonResponse(
                    {"success": False, "error": "min_distance_km must be >= 0."},
                    status=400
                )
            rate_obj.min_distance_km = min_val
            changes_made = True
        except (InvalidOperation, ValueError):
            return JsonResponse(
                {"success": False, "error": "Invalid min_distance_km value."},
                status=400
            )

    # -----------------------------
    # Update max_distance_km
    # -----------------------------
    if max_km is not None:
        if max_km in ("", "null"):
            rate_obj.max_distance_km = None
            changes_made = True
        else:
            try:
                max_val = Decimal(str(max_km))
                if max_val < rate_obj.min_distance_km:
                    return JsonResponse(
                        {"success": False, "error": "max_distance_km must be >= min_distance_km."},
                        status=400
                    )
                rate_obj.max_distance_km = max_val
                changes_made = True
            except (InvalidOperation, ValueError):
                return JsonResponse(
                    {"success": False, "error": "Invalid max_distance_km value."},
                    status=400
                )

    # -----------------------------
    # Update rate
    # -----------------------------
    if rate is not None:
        try:
            rate_val = Decimal(str(rate))
            if rate_val < 0:
                return JsonResponse(
                    {"success": False, "error": "rate must be >= 0."},
                    status=400
                )
            rate_obj.rate = rate_val
            changes_made = True
        except (InvalidOperation, ValueError):
            return JsonResponse(
                {"success": False, "error": "Invalid rate value."},
                status=400
            )

    # -----------------------------
    # No-op protection
    # -----------------------------
    if not changes_made:
        return JsonResponse(
            {"success": False, "message": "No fields were updated."},
            status=400
        )

    # -----------------------------
    # Save changes
    # -----------------------------
    try:
        rate_obj.save()
    except Exception as e:
        return JsonResponse(
            {"success": False, "error": f"Failed to save rate: {str(e)}"},
            status=500
        )

    # -----------------------------
    # Response
    # -----------------------------
    return JsonResponse(
        {
            "success": True,
            "message": "Delivery rate updated successfully.",
            "rate": {
                "id": rate_obj.id,
                "min_distance_km": float(rate_obj.min_distance_km),
                "max_distance_km": float(rate_obj.max_distance_km) if rate_obj.max_distance_km else None,
                "rate": float(rate_obj.rate),
            },
        },
        status=200
    )


# 🗑️ DELETE DELIVERY RATE
# @csrf_exempt
# @require_http_methods(["DELETE", "POST"])  # Allow both DELETE and POST for compatibility
# def delete_delivery_rate(request, rate_id):
#     """
#     Hard delete a DeliveryDistanceRate entry.
#     URL: /api/deliveryRates/<id>/delete/
#     """
#     try:
#         # Check if rate exists
#         try:
#             rate_obj = DeliveryDistanceRate.objects.get(id=rate_id)
#         except DeliveryDistanceRate.DoesNotExist:
#             return JsonResponse(
#                 {"success": False, "error": f"Rate with ID {rate_id} not found."},
#                 status=404
#             )

#         # Store info before deletion for response
#         rate_info = {
#             "id": rate_obj.id,
#             "min_distance_km": float(rate_obj.min_distance_km) if rate_obj.min_distance_km else 0.0,
#             "max_distance_km": float(rate_obj.max_distance_km) if rate_obj.max_distance_km else None,
#             "rate": float(rate_obj.rate) if rate_obj.rate else 0.0,
#         }

#         # Delete the rate
#         rate_obj.delete()

#         return JsonResponse({
#             "success": True,
#             "message": f"Rate ID {rate_id} deleted successfully.",
#             "deleted_rate": rate_info
#         }, status=200)

#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         return JsonResponse({
#             "success": False,
#             "error": f"Internal server error: {str(e)}",
#             "error_type": type(e).__name__
#         }, status=500)


@csrf_protect
@admin_auth_required
@require_http_methods(["DELETE", "POST"])  # DELETE preferred, POST allowed for compatibility
def delete_delivery_rate(request, rate_id):
    """
    PRODUCTION: Hard delete a DeliveryDistanceRate entry.

    URL:
      DELETE /api/deliveryRates/<id>/delete/

    Notes:
    - Admin only
    - Irreversible (hard delete)
    - Does NOT affect historical orders (rates are copied at order creation)
    """

    # -----------------------------
    # Validate rate exists
    # -----------------------------
    try:
        rate_obj = DeliveryDistanceRate.objects.get(id=rate_id)
    except DeliveryDistanceRate.DoesNotExist:
        return JsonResponse(
            {"success": False, "error": f"Rate with ID {rate_id} not found."},
            status=404
        )

    # -----------------------------
    # Store info before deletion
    # -----------------------------
    deleted_rate_info = {
        "id": rate_obj.id,
        "min_distance_km": float(rate_obj.min_distance_km),
        "max_distance_km": float(rate_obj.max_distance_km) if rate_obj.max_distance_km else None,
        "rate": float(rate_obj.rate),
    }

    # -----------------------------
    # Perform deletion
    # -----------------------------
    try:
        rate_obj.delete()
    except Exception as e:
        return JsonResponse(
            {"success": False, "error": f"Failed to delete rate: {str(e)}"},
            status=500
        )

    # -----------------------------
    # Response
    # -----------------------------
    return JsonResponse(
        {
            "success": True,
            "message": f"Rate ID {rate_id} deleted successfully.",
            "deleted_rate": deleted_rate_info,
        },
        status=200
    )





# @csrf_exempt
# def get_pharmacy_details_admin(request, pharmacy_id=None):
#     try:
#         # 🟠 CASE 1: No ID → return ALL pharmacies (summary)
#         if pharmacy_id is None:
#             pharmacies = Pharmacy.objects.all().order_by("name")

#             pharmacy_list = []
#             for p in pharmacies:
#                 total_orders = DeliveryOrder.objects.filter(
#                     pharmacy=p
#                 ).exclude(status="cancelled").count()

#                 total_outstanding = Invoice.objects.filter(
#                     pharmacy=p
#                 ).exclude(status="paid").aggregate(
#                     total=Sum("total_amount")
#                 )["total"] or 0

#                 pharmacy_list.append({
#                     "id": p.id,
#                     "name": p.name,
#                     "store_address" : p.store_address,
#                     "city": p.city,
#                     "postal_code" : p.postal_code,
#                     "province": p.province,
#                     "phone_number": p.phone_number,
#                     "email": p.email,
#                     "active": p.active,
#                     "total_valid_orders": total_orders,
#                     "total_outstanding_amount": float(total_outstanding),
#                 })

#             return JsonResponse({
#                 "success": True,
#                 "pharmacies": pharmacy_list,
#             }, status=200)

#         # 🟢 CASE 2: ID provided → return SINGLE pharmacy with full info
#         pharmacy = Pharmacy.objects.get(id=pharmacy_id)

#         total_orders = DeliveryOrder.objects.filter(
#             pharmacy=pharmacy
#         ).exclude(status="cancelled").count()

#         total_outstanding = Invoice.objects.filter(
#             pharmacy=pharmacy
#         ).exclude(status="paid").aggregate(
#             total=Sum("total_amount")
#         )["total"] or 0

#         orders_qs = DeliveryOrder.objects.filter(
#             pharmacy=pharmacy
#         ).order_by("-created_at")

#         orders = []
#         for o in orders_qs:
#             orders.append({
#                 "id": o.id,
#                 "pickup_address": o.pickup_address,
#                 "pickup_city": o.pickup_city,
#                 "pickup_day": str(o.pickup_day),
#                 "drop_address": o.drop_address,
#                 "drop_city": o.drop_city,
#                 "status": o.status,
#                 "rate": float(o.rate),
#                 "customer_name": o.customer_name,
#                 "driver": o.driver.name if o.driver else None,
#                 "created_at": o.created_at.strftime("%Y-%m-%d %H:%M:%S"),
#                 "updated_at": o.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
#             })

#         invoice_qs = Invoice.objects.filter(
#             pharmacy=pharmacy
#         ).order_by("-created_at")

#         invoices = []
#         for inv in invoice_qs:
#             invoices.append({
#                 "invoice_id": inv.id,
#                 "start_date": str(inv.start_date),
#                 "end_date": str(inv.end_date),
#                 "total_orders": inv.total_orders,
#                 "total_amount": float(inv.total_amount),
#                 "due_date": str(inv.due_date),
#                 "status": inv.status,
#                 "pdf_url": inv.pdf_url,
#                 "stripe_payment_id": inv.stripe_payment_id,
#             })

#         pharmacy_data = {
#             "id": pharmacy.id,
#             "name": pharmacy.name,
#             "store_address": pharmacy.store_address,
#             "city": pharmacy.city,
#             "province": pharmacy.province,
#             "postal_code": pharmacy.postal_code,
#             "country": pharmacy.country,
#             "phone_number": pharmacy.phone_number,
#             "email": pharmacy.email,
#             "active": pharmacy.active,
#             "created_at": pharmacy.created_at.strftime("%Y-%m-%d %H:%M:%S"),
#         }

#         return JsonResponse({
#             "success": True,
#             "pharmacy": pharmacy_data,
#             "total_valid_orders": total_orders,
#             "total_outstanding_amount": float(total_outstanding),
#             "orders": orders,
#             "invoices": invoices,
#         }, status=200)

#     except Pharmacy.DoesNotExist:
#         return JsonResponse({"success": False, "message": "Pharmacy not found"}, status=404)
#     except Exception as e:
#         return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def get_pharmacy_details_admin(request, pharmacy_id=None):
    try:
        # =========================================================
        # 🟠 CASE 1: ALL PHARMACIES (SUMMARY VIEW)
        # =========================================================
        if pharmacy_id is None:
            pharmacies = Pharmacy.objects.all().order_by("name")

            pharmacy_list = []
            for p in pharmacies:
                total_orders = DeliveryOrder.objects.filter(
                    pharmacy=p
                ).count()  # ✅ includes cancelled

                total_outstanding = Invoice.objects.filter(
                    pharmacy=p
                ).exclude(status="paid").aggregate(
                    total=Sum("total_amount")
                )["total"] or 0

                # ✅ CC POINTS (INLINE)
                try:
                    cc_points_balance = p.cc_points.points_balance
                except Exception:
                    cc_points_balance = 0

                pharmacy_list.append({
                    "id": p.id,
                    "name": p.name,
                    "store_address": p.store_address,
                    "city": p.city,
                    "province": p.province,
                    "postal_code": p.postal_code,
                    "country": p.country,
                    "phone_number": p.phone_number,
                    "email": p.email,
                    "active": p.active,

                    # ✅ Business hours
                    "business_hours": p.business_hours,

                    # ✅ CC Points
                    "cc_points_balance": cc_points_balance,

                    # KPIs
                    "total_orders": total_orders,
                    "total_outstanding_amount": float(total_outstanding),

                    # Time (LOCAL)
                    "created_at_local": _to_local_iso(p.created_at),
                })

            return JsonResponse({
                "success": True,
                "count": len(pharmacy_list),
                "pharmacies": pharmacy_list,
                "timezone": str(settings.USER_TIMEZONE),
            }, status=200)

        # =========================================================
        # 🟢 CASE 2: SINGLE PHARMACY (FULL ADMIN VIEW)
        # =========================================================
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)

        total_orders = DeliveryOrder.objects.filter(
            pharmacy=pharmacy
        ).count()  # ✅ includes cancelled

        total_outstanding = Invoice.objects.filter(
            pharmacy=pharmacy
        ).exclude(status="paid").aggregate(
            total=Sum("total_amount")
        )["total"] or 0

        # ✅ CC POINTS (INLINE)
        try:
            cc_points_balance = pharmacy.cc_points.points_balance
        except Exception:
            cc_points_balance = 0

        # =========================================================
        # Orders (FULL MODEL COVERAGE)
        # =========================================================
        orders_qs = (
            DeliveryOrder.objects
            .select_related("driver", "pharmacy")
            .filter(pharmacy=pharmacy)
            .order_by("-created_at")
        )

        orders = []
        for o in orders_qs:
            orders.append({
                "id": o.id,

                # Pharmacy snapshot
                "pharmacy": {
                    "id": pharmacy.id,
                    "name": pharmacy.name,
                    "city": pharmacy.city,
                    "province": pharmacy.province,
                    "phone_number": pharmacy.phone_number,
                    "email": pharmacy.email,
                    "active": pharmacy.active,
                    "business_hours": pharmacy.business_hours,
                },

                # Pickup / Drop
                "pickup_address": o.pickup_address,
                "pickup_city": o.pickup_city,
                "pickup_day": str(o.pickup_day),
                "drop_address": o.drop_address,
                "drop_city": o.drop_city,

                # Customer
                "customer_name": o.customer_name,
                "customer_phone": o.customer_phone,
                "alternate_contact": o.alternate_contact or "",

                # Instructions
                "delivery_notes": o.delivery_notes or "",
                "signature_required": o.signature_required,
                "id_verification_required": o.id_verification_required,

                # Proof / Verification
                "signature_ack_url": o.signature_ack_url,
                "id_verified": o.id_verified,
                "is_delivered": o.is_delivered,

                # Financial
                "rate": float(o.rate),

                # Status
                "status": o.status,

                # Driver (FULL ADMIN VIEW)
                "driver": ({
                    "id": o.driver.id,
                    "name": o.driver.name,
                    "email": o.driver.email,
                    "phone_number": o.driver.phone_number,
                    "vehicle_number": o.driver.vehicle_number,
                    "active": o.driver.active,
                    "identity_url": o.driver.identity_url,
                    "created_at_local": _to_local_iso(o.driver.created_at),
                } if o.driver else None),

                # Timestamps (LOCAL)
                "created_at_local": _to_local_iso(o.created_at),
                "updated_at_local": _to_local_iso(o.updated_at),
                "delivered_at_local": _to_local_iso(o.delivered_at),
            })

        # =========================================================
        # Invoices
        # =========================================================
        invoices = []
        for inv in Invoice.objects.filter(pharmacy=pharmacy).order_by("-created_at"):
            invoices.append({
                "invoice_id": inv.id,
                "start_date": str(inv.start_date),
                "end_date": str(inv.end_date),
                "total_orders": inv.total_orders,
                "total_amount": float(inv.total_amount),
                "due_date": str(inv.due_date),
                "status": inv.status,
                "pdf_url": inv.pdf_url,
                "stripe_payment_id": inv.stripe_payment_id,
                "created_at_local": _to_local_iso(inv.created_at),
            })

        # =========================================================
        # Final Response
        # =========================================================
        return JsonResponse({
            "success": True,
            "pharmacy": {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "store_address": pharmacy.store_address,
                "city": pharmacy.city,
                "province": pharmacy.province,
                "postal_code": pharmacy.postal_code,
                "country": pharmacy.country,
                "phone_number": pharmacy.phone_number,
                "email": pharmacy.email,
                "active": pharmacy.active,
                "business_hours": pharmacy.business_hours,

                # ✅ CC Points (FULL VIEW)
                "cc_points": {
                    "points_balance": cc_points_balance
                },

                "created_at_local": _to_local_iso(pharmacy.created_at),
            },
            "total_orders": total_orders,
            "total_outstanding_amount": float(total_outstanding),
            "orders": orders,
            "invoices": invoices,
            "timezone": str(settings.USER_TIMEZONE),
        }, status=200)

    except Pharmacy.DoesNotExist:
        return JsonResponse({
            "success": False,
            "error": "Pharmacy not found"
        }, status=404)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)



@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def get_driver_details_admin(request, driver_id=None):
    """
    Admin-only Driver Details API
    - Secure (CSRF + Admin auth)
    - GET only
    - All datetime fields returned in USER_TIMEZONE
    """

    user_tz = settings.USER_TIMEZONE

    def to_local_iso(dt):
        if not dt:
            return None
        return timezone.localtime(dt, user_tz).isoformat()

    try:
        # 🟠 CASE 1: ALL drivers (summary)
        if driver_id is None:
            drivers = Driver.objects.all().order_by("name")

            driver_list = []
            for d in drivers:
                total_deliveries = DeliveryOrder.objects.filter(
                    driver=d
                ).exclude(status="cancelled").count()

                outstanding_amount = (
                    DriverInvoice.objects.filter(driver=d)
                    .exclude(status="paid")
                    .aggregate(total=Sum("total_amount"))["total"] or 0
                )

                active_orders_count = DeliveryOrder.objects.filter(
                    driver=d,
                    status__in=["pending", "accepted", "inTransit", "picked_up"]
                ).count()

                driver_list.append({
                    "id": d.id,
                    "name": d.name,
                    "phone_number": d.phone_number,
                    "email": d.email,
                    "vehicle_number": d.vehicle_number,
                    "active": d.active,
                    "identity_url": d.identity_url,
                    "created_at_local": to_local_iso(d.created_at),

                    # 🔹 NEW FIELDS
                    "current_active_orders_count": active_orders_count,
                    "has_identity_uploaded": bool(d.identity_url),

                    "total_completed_deliveries": total_deliveries,
                    "total_outstanding_amount": float(outstanding_amount),
                })

            return JsonResponse({
                "success": True,
                "timezone": str(user_tz),
                "drivers": driver_list,
                "count": len(driver_list),
                "generated_at_local": to_local_iso(timezone.now()),
            }, status=200)

        # 🟢 CASE 2: SINGLE driver (full details)
        driver = Driver.objects.get(id=driver_id)

        total_deliveries = DeliveryOrder.objects.filter(
            driver=driver
        ).exclude(status="cancelled").count()

        outstanding_amount = (
            DriverInvoice.objects.filter(driver=driver)
            .exclude(status="paid")
            .aggregate(total=Sum("total_amount"))["total"] or 0
        )

        active_orders_count = DeliveryOrder.objects.filter(
            driver=driver,
            status__in=["pending", "accepted", "inTransit", "picked_up"]
        ).count()

        # Orders
        orders = []
        for o in (
            DeliveryOrder.objects
            .filter(driver=driver)
            .select_related("pharmacy")
            .prefetch_related("images", "tracking_entries")
            .order_by("-created_at")
        ):
            orders.append({
                "order_id": o.id,
                "pharmacy": o.pharmacy.name if o.pharmacy else None,
                "pickup_address": o.pickup_address,
                "pickup_city": o.pickup_city,
                "pickup_day": str(o.pickup_day),
                "drop_address": o.drop_address,
                "drop_city": o.drop_city,
                "status": o.status,
                "rate": float(o.rate),
                "customer_name": o.customer_name,
                "created_at_local": to_local_iso(o.created_at),
                "updated_at_local": to_local_iso(o.updated_at),
                "delivered_at_local": to_local_iso(o.delivered_at),
                "images": [
                    {
                        "id": img.id,
                        "stage": img.stage,
                        "image_url": img.image_url,
                        "uploaded_at_local": to_local_iso(img.uploaded_at),
                    }
                    for img in o.images.all()
                ],
                "tracking_entries": [
                    {
                        "id": t.id,
                        "step": t.step,
                        "performed_by": t.performed_by,
                        "note": t.note,
                        "image_url": t.image_url,
                        "pharmacy": t.pharmacy.name if t.pharmacy else None,
                        "timestamp_local": to_local_iso(t.timestamp),
                    }
                    for t in o.tracking_entries.all().order_by("timestamp")
                ],
            })

        invoices = [
            {
                "invoice_id": inv.id,
                "start_date": str(inv.start_date),
                "end_date": str(inv.end_date),
                "total_deliveries": inv.total_deliveries,
                "total_amount": float(inv.total_amount),
                "due_date": str(inv.due_date),
                "status": inv.status,
                "pdf_url": inv.pdf_url,
                "created_at_local": to_local_iso(inv.created_at),
            }
            for inv in DriverInvoice.objects.filter(driver=driver).order_by("-created_at")
        ]

        return JsonResponse({
            "success": True,
            "timezone": str(user_tz),
            "driver": {
                "id": driver.id,
                "name": driver.name,
                "phone_number": driver.phone_number,
                "email": driver.email,
                "vehicle_number": driver.vehicle_number,
                "active": driver.active,
                "identity_url": driver.identity_url,
                "created_at_local": to_local_iso(driver.created_at),

                # 🔹 NEW FIELDS
                "current_active_orders_count": active_orders_count,
                "has_identity_uploaded": bool(driver.identity_url),
            },
            "total_completed_deliveries": total_deliveries,
            "total_outstanding_amount": float(outstanding_amount),
            "orders": orders,
            "invoices": invoices,
            "generated_at_local": to_local_iso(timezone.now()),
        }, status=200)

    except Driver.DoesNotExist:
        return JsonResponse({"success": False, "message": "Driver not found"}, status=404)

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)




def validate_business_hours(business_hours: dict):
    """
    Validates business_hours JSON structure.
    Expected:
    {
      "Mon": {"open": "09:00", "close": "18:00"} OR "closed",
      ...
    }
    """
    allowed_days = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

    if not isinstance(business_hours, dict):
        raise ValueError("business_hours must be an object")

    for day, value in business_hours.items():
        if day not in allowed_days:
            raise ValueError(f"Invalid day '{day}' in business_hours")

        if value == "closed":
            continue

        if not isinstance(value, dict):
            raise ValueError(f"{day} must be 'closed' or an object")

        if "open" not in value or "close" not in value:
            raise ValueError(f"{day} must contain 'open' and 'close'")

        try:
            datetime.strptime(value["open"], "%H:%M")
            datetime.strptime(value["close"], "%H:%M")
        except ValueError:
            raise ValueError(f"{day} open/close must be in HH:MM format")


@csrf_protect
@admin_auth_required
@require_http_methods(["POST"])
def add_pharmacy(request):
    """
    PRODUCTION: Create Pharmacy (Admin Only)

    - Secure (CSRF + Admin Auth)
    - POST only
    - Accepts optional business_hours
    - Uses default business hours if not provided
    - Password defaults to '123456' (hashed)
    - Business hours are LOCAL TIME (no timezone conversion)
    - Sends welcome email to pharmacy with login credentials
    - Sends notification email to office
    """

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse({
            "success": False,
            "error": "Invalid JSON payload"
        }, status=400)

    # Required fields
    required_fields = [
        "name",
        "store_address",
        "city",
        "province",
        "postal_code",
        "country",
        "phone_number",
        "email",
    ]

    missing = [f for f in required_fields if not payload.get(f)]
    if missing:
        return JsonResponse({
            "success": False,
            "error": "Missing required fields",
            "missing_fields": missing
        }, status=400)

    # Business hours (optional)
    business_hours = payload.get("business_hours")

    try:
        if business_hours:
            validate_business_hours(business_hours)
        else:
            business_hours = default_business_hours()
    except ValueError as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=400)

    try:
        pharmacy = Pharmacy.objects.create(
            name=payload["name"].strip(),
            store_address=payload["store_address"].strip(),
            city=payload["city"].strip(),
            province=payload["province"].strip(),
            postal_code=payload["postal_code"].strip(),
            country=payload["country"].strip(),
            phone_number=payload["phone_number"].strip(),
            email=payload["email"].strip(),
            password="123456",
            active=payload.get("active", True),
            business_hours=business_hours,
        )

        # ---- Time handling (DB=UTC, Display=Local) ----
        created_at_utc = timezone.now()  # DB truth (UTC)
        try:
            created_at_local = created_at_utc.astimezone(USER_TZ)
        except Exception:
            created_at_local = created_at_utc
        
        created_at = created_at_local.strftime("%b %d, %Y %H:%M %Z")

        # ---- Send welcome email to pharmacy ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            logo_url = settings.LOGO_URL

            html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to {settings.COMPANY_OPERATING_NAME} • Pharmacy Registration</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Registration confirmed — welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Welcome to {settings.COMPANY_OPERATING_NAME}
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {pharmacy.name or "there"}, your pharmacy is all set 🎉
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Thanks for registering with <strong>{settings.COMPANY_OPERATING_NAME}</strong> an operating name of {settings.CORPORATION_NAME} and joining the <strong>Cana Family by {settings.COMPANY_SUB_GROUP_NAME}</strong>.
                  We're excited to help your team coordinate secure, trackable, and timely deliveries with a dashboard
                  designed for pharmacies.
                </p>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    <li>Live order tracking with photo proof at each stage</li>
                    <li>Professional Delivery Management System using Customer ID and Signature Verifications
                    <li>Smart weekly invoices and transparent earnings</li>
                    <li>Secure driver handover and delivery confirmations</li>
                  </ul>
                </div>

                <div style="margin:20px 0;background:#fef3c7;border:1px solid #fbbf24;border-radius:12px;padding:16px 18px;">
                  <h2 style="margin:0 0 12px;font:700 16px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
                    🔐 Your Login Credentials
                  </h2>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr>
                      <td style="padding:6px 0;color:#78350f;font-weight:600;">Username:</td>
                      <td style="padding:6px 0;color:#78350f;">{pharmacy.email}</td>
                    </tr>
                    <tr>
                      <td style="padding:6px 0;color:#78350f;font-weight:600;">Password:</td>
                      <td style="padding:6px 0;color:#78350f;font-family:monospace;font-weight:600;">123456</td>
                    </tr>
                  </table>
                  <div style="margin-top:14px;padding-top:14px;border-top:1px solid #fbbf24;">
                    <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#92400e;">
                      ⚠️ <strong>Important Security Notice:</strong>
                    </p>
                    <p style="margin:6px 0 0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
                      For your security, please change your password immediately after logging in. Navigate to: <strong>My Profile → Security Settings → Change Password</strong>
                    </p>
                  </div>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Registered on <strong style="color:{brand_primary_dark};">{created_at}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Questions or need a hand? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Welcome aboard — we're thrilled to partner with you.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {created_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                f"Welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}!\n\n"
                f"Hi {pharmacy.name or 'there'}, your pharmacy registration is confirmed.\n"
                "• Live order tracking with photo proof\n"
                "• Weekly invoices and transparent earnings\n"
                "• Secure handover and delivery confirmations\n\n"
                "Your Login Credentials:\n"
                f"Username: {pharmacy.email}\n"
                "Password: 123456\n\n"
                "IMPORTANT: For your security, please change your password immediately after logging in.\n"
                "Navigate to: My Profile → Security Settings → Change Password\n\n"
                "Questions? Just reply to this email.\n"
            )

            _send_html_email_help_desk(
                subject=f"Welcome to {settings.COMPANY_OPERATING_NAME} • Pharmacy Registration Confirmed",
                to_email=pharmacy.email,
                html=html,
                text_fallback=text,
            )
        except Exception:
            logger.exception("Failed to send pharmacy registration email")
        
        # ---- Send office notification email ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            logo_url = settings.LOGO_URL

            office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Pharmacy Registration • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .info-row {{ background: #1e293b !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      New Pharmacy Registered
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  New Pharmacy Registration
                </h1>
                <p style="margin:0 0 20px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  A new pharmacy has been successfully added to the {settings.COMPANY_OPERATING_NAME} platform by an administrator.
                </p>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Pharmacy Name</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{pharmacy.name}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.email}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.phone_number}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Address</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.store_address}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">City</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.city}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Province</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.province}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Postal Code</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.postal_code}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Country</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.country}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Registration Time</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{created_at}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Pharmacy ID</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{pharmacy.id}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Status</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{"Active" if pharmacy.active else "Inactive"}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Default Password</td>
                      <td style="padding:12px 18px;color:#0f172a;font-family:monospace;border-top:1px solid #e2e8f0;">123456</td>
                    </tr>
                  </table>
                </div>

                <div style="margin:20px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    <strong>✓ Registration Complete</strong> — The pharmacy has been added to the system and received their welcome email with login credentials.
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  This is an automated notification from the {settings.COMPANY_OPERATING_NAME} registration system.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {created_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            office_text = (
                f"New Pharmacy Registration on {settings.COMPANY_OPERATING_NAME}\n\n"
                f"Pharmacy Name: {pharmacy.name}\n"
                f"Email: {pharmacy.email}\n"
                f"Phone: {pharmacy.phone_number}\n"
                f"Address: {pharmacy.store_address}\n"
                f"City: {pharmacy.city}\n"
                f"Province: {pharmacy.province}\n"
                f"Postal Code: {pharmacy.postal_code}\n"
                f"Country: {pharmacy.country}\n"
                f"Registration Time: {created_at}\n"
                f"Pharmacy ID: {pharmacy.id}\n"
                f"Status: {'Active' if pharmacy.active else 'Inactive'}\n"
                f"Default Password: 123456\n\n"
                "The pharmacy has been added to the system and received their welcome email with login credentials.\n"
            )

            _send_html_email_help_desk(
                subject=f"New Pharmacy Registration: {pharmacy.name}",
                to_email=settings.EMAIL_ADMIN_OFFICE,
                html=office_html,
                text_fallback=office_text,
            )
        except Exception:
            logger.exception("Failed to send office notification email for pharmacy registration")

        return JsonResponse({
            "success": True,
            "message": "Pharmacy created successfully",
            "pharmacy": {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "email": pharmacy.email,
                "phone_number": pharmacy.phone_number,
                "city": pharmacy.city,
                "province": pharmacy.province,
                "active": pharmacy.active,
                "business_hours": pharmacy.business_hours,
                "created_at_local": timezone.localtime(
                    pharmacy.created_at,
                    settings.USER_TIMEZONE
                ).isoformat(),
                "timezone": str(settings.USER_TIMEZONE),
            }
        }, status=201)

    except IntegrityError:
        return JsonResponse({
            "success": False,
            "error": "A pharmacy with this email already exists"
        }, status=400)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": "Internal server error",
            "details": str(e)
        }, status=500)



@require_http_methods(["POST"])
@csrf_protect
@admin_auth_required
def add_driver(request):
    """
    Admin-only API to create a new driver.
    - Stores timestamps in UTC
    - Returns responses in settings.USER_TIMEZONE
    - Sends welcome email to driver with login credentials
    - Sends notification email to office
    """

    # 1️⃣ Parse JSON payload
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

    # 2️⃣ Required fields validation
    required_fields = ["name", "phone_number", "email"]
    missing_fields = [f for f in required_fields if not data.get(f)]

    if missing_fields:
        return JsonResponse(
            {
                "success": False,
                "message": "Missing required fields.",
                "missing_fields": missing_fields,
            },
            status=400,
        )

    # 3️⃣ Normalize inputs
    name = data.get("name", "").strip()
    phone_number = data.get("phone_number", "").strip()
    email = data.get("email", "").strip().lower()
    vehicle_number = data.get("vehicle_number", "").strip()
    active = data.get("active", True)

    try:
        # 4️⃣ Create driver (password auto-hashed in model save())
        driver = Driver.objects.create(
            name=name,
            phone_number=phone_number,
            email=email,
            vehicle_number=vehicle_number,
            active=active,
            # identity_url intentionally left empty (allowed)
        )

        # 5️⃣ Convert UTC → USER_TIMEZONE for response
        local_created_at = timezone.localtime(
            driver.created_at, settings.USER_TIMEZONE
        )

        # ---- Time handling (DB=UTC, Display=Local) ----
        created_at_utc = timezone.now()  # DB truth (UTC)
        try:
            created_at_local = created_at_utc.astimezone(settings.USER_TIMEZONE)
        except Exception:
            created_at_local = created_at_utc
        
        created_at = created_at_local.strftime("%b %d, %Y %H:%M %Z")

        # ---- Send welcome email to driver ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            logo_url = settings.LOGO_URL

            html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to {settings.COMPANY_OPERATING_NAME} • Driver Registration</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Registration confirmed — welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left">
                    <img src="{logo_url}"
                        alt="{settings.COMPANY_OPERATING_NAME}"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Welcome to {settings.COMPANY_OPERATING_NAME}
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {driver.name or "there"}, you're all set 🎉
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Thanks for joining <strong>{settings.COMPANY_OPERATING_NAME}</strong> an operating name of {settings.CORPORATION_NAME} and the <strong>Cana Family by {settings.COMPANY_SUB_GROUP_NAME}</strong>.
                  We're excited to have you on the team! Your driver account has been created and you can now access the delivery platform.
                </p>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    <li>Real-time delivery assignments and route optimization</li>
                    <li>Photo proof capture at pickup and delivery stages</li>
                    <li>Customer ID and signature verification system</li>
                    <li>Transparent earnings tracking and weekly payouts</li>
                    <li>Secure communication with pharmacies and support</li>
                  </ul>
                </div>

                <div style="margin:20px 0;background:#fef3c7;border:1px solid #fbbf24;border-radius:12px;padding:16px 18px;">
                  <h2 style="margin:0 0 12px;font:700 16px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
                    🔐 Your Login Credentials
                  </h2>
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr>
                      <td style="padding:6px 0;color:#78350f;font-weight:600;">Username:</td>
                      <td style="padding:6px 0;color:#78350f;">{driver.email}</td>
                    </tr>
                    <tr>
                      <td style="padding:6px 0;color:#78350f;font-weight:600;">Password:</td>
                      <td style="padding:6px 0;color:#78350f;font-family:monospace;font-weight:600;">123456</td>
                    </tr>
                  </table>
                  <div style="margin-top:14px;padding-top:14px;border-top:1px solid #fbbf24;">
                    <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#92400e;">
                      ⚠️ <strong>Important Security Notice:</strong>
                    </p>
                    <p style="margin:6px 0 0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
                      For your security, please change your password immediately after logging in. Navigate to: <strong>My Profile → Security Settings → Change Password</strong>
                    </p>
                  </div>
                </div>

                <div style="margin:20px 0;background:#e0f2fe;border:1px solid #0ea5e9;border-radius:12px;padding:16px 18px;">
                  <h2 style="margin:0 0 12px;font:700 16px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#075985;">
                    📸 Next Step: Add Your Front-Facing Photo
                  </h2>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#075985;">
                    After changing your password, please upload a clear front-facing photo of yourself in the <strong>My Identity</strong> section. This photo is required for successful deliveries and package handovers to ensure security and accountability.
                  </p>
                  <p style="margin:10px 0 0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0c4a6e;">
                    Navigate to: <strong>My Profile → My Identity → Upload Photo</strong>
                  </p>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Registered on <strong style="color:{brand_primary_dark};">{created_at}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Questions or need a hand? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Welcome aboard — we're thrilled to have you on the team.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {created_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                f"Welcome to {settings.COMPANY_OPERATING_NAME} and the Cana Family by {settings.COMPANY_SUB_GROUP_NAME}!\n\n"
                f"Hi {driver.name or 'there'}, your driver registration is confirmed.\n"
                "• Real-time delivery assignments and route optimization\n"
                "• Photo proof capture at pickup and delivery\n"
                "• Customer ID and signature verification\n"
                "• Transparent earnings tracking and weekly payouts\n\n"
                "Your Login Credentials:\n"
                f"Username: {driver.email}\n"
                "Password: 123456\n\n"
                "IMPORTANT: For your security, please change your password immediately after logging in.\n"
                "Navigate to: My Profile → Security Settings → Change Password\n\n"
                "NEXT STEP: After changing your password, please upload a clear front-facing photo in the My Identity section.\n"
                "This photo is required for successful deliveries and package handovers.\n"
                "Navigate to: My Profile → My Identity → Upload Photo\n\n"
                "Questions? Just reply to this email.\n"
            )

            _send_html_email_help_desk(
                subject=f"Welcome to {settings.COMPANY_OPERATING_NAME} • Driver Registration Confirmed",
                to_email=driver.email,
                html=html,
                text_fallback=text,
            )
        except Exception:
            logger.exception("Failed to send driver registration email")
        
        # ---- Send office notification email ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            logo_url = settings.LOGO_URL

            office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Driver Registration • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .info-row {{ background: #1e293b !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      New Driver Registered
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  New Driver Registration
                </h1>
                <p style="margin:0 0 20px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  A new driver has been successfully added to the {settings.COMPANY_OPERATING_NAME} platform by an administrator.
                </p>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Driver Name</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{driver.name}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{driver.email}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{driver.phone_number}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Vehicle Number</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{driver.vehicle_number if driver.vehicle_number else "Not provided"}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Registration Time</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{created_at}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Driver ID</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{driver.id}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Status</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{"Active" if driver.active else "Inactive"}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Default Password</td>
                      <td style="padding:12px 18px;color:#0f172a;font-family:monospace;border-top:1px solid #e2e8f0;">123456</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Identity Photo</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">Pending upload</td>
                    </tr>
                  </table>
                </div>

                <div style="margin:20px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    <strong>✓ Registration Complete</strong> — The driver has been added to the system and received their welcome email with login credentials. They will need to upload their identity photo before starting deliveries.
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  This is an automated notification from the {settings.COMPANY_OPERATING_NAME} registration system.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {created_at_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            office_text = (
                f"New Driver Registration on {settings.COMPANY_OPERATING_NAME}\n\n"
                f"Driver Name: {driver.name}\n"
                f"Email: {driver.email}\n"
                f"Phone: {driver.phone_number}\n"
                f"Vehicle Number: {driver.vehicle_number if driver.vehicle_number else 'Not provided'}\n"
                f"Registration Time: {created_at}\n"
                f"Driver ID: {driver.id}\n"
                f"Status: {'Active' if driver.active else 'Inactive'}\n"
                f"Default Password: 123456\n"
                f"Identity Photo: Pending upload\n\n"
                "The driver has been added to the system and received their welcome email with login credentials.\n"
                "They will need to upload their identity photo before starting deliveries.\n"
            )

            _send_html_email_help_desk(
                subject=f"New Driver Registration: {driver.name}",
                to_email=settings.EMAIL_ADMIN_OFFICE,
                html=office_html,
                text_fallback=office_text,
            )
        except Exception:
            logger.exception("Failed to send office notification email for driver registration")

        driver_data = {
            "id": driver.id,
            "name": driver.name,
            "phone_number": driver.phone_number,
            "email": driver.email,
            "vehicle_number": driver.vehicle_number,
            "active": driver.active,
            "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse(
            {
                "success": True,
                "message": "Driver created successfully.",
                "driver": driver_data,
            },
            status=201,
        )

    except IntegrityError:
        # Unique constraint violation (email)
        return JsonResponse(
            {
                "success": False,
                "message": "A driver with this email already exists.",
                "field": "email",
            },
            status=400,
        )

    except Exception:
        # Do NOT leak internal errors in prod
        return JsonResponse(
            {
                "success": False,
                "message": "Something went wrong while creating the driver.",
            },
            status=500,
        )



# @csrf_exempt
# def edit_pharmacy(request, pharmacy_id):
#     if request.method != "PUT":
#         return JsonResponse(
#             {"success": False, "message": "Only PUT method is allowed."},
#             status=405,
#         )

#     try:
#         pharmacy = Pharmacy.objects.get(id=pharmacy_id)
#     except Pharmacy.DoesNotExist:
#         return JsonResponse(
#             {"success": False, "message": "Pharmacy not found."},
#             status=404,
#         )

#     try:
#         data = json.loads(request.body.decode("utf-8"))
#     except json.JSONDecodeError:
#         return JsonResponse(
#             {"success": False, "message": "Invalid JSON payload."},
#             status=400,
#         )

#     # Editable fields
#     editable_fields = [
#         "name",
#         "store_address",
#         "city",
#         "province",
#         "postal_code",
#         "country",
#         "phone_number",
#         "email",
#         "active",
#     ]

#     # Update only provided fields
#     for field in editable_fields:
#         if field in data:
#             setattr(pharmacy, field, data[field].strip() if isinstance(data[field], str) else data[field])

#     try:
#         pharmacy.save()

#         updated_data = {
#             "id": pharmacy.id,
#             "name": pharmacy.name,
#             "store_address": pharmacy.store_address,
#             "city": pharmacy.city,
#             "province": pharmacy.province,
#             "postal_code": pharmacy.postal_code,
#             "country": pharmacy.country,
#             "phone_number": pharmacy.phone_number,
#             "email": pharmacy.email,
#             "active": pharmacy.active,
#             "created_at": pharmacy.created_at.strftime("%Y-%m-%d %H:%M:%S"),
#         }

#         return JsonResponse(
#             {
#                 "success": True,
#                 "message": "Pharmacy updated successfully.",
#                 "pharmacy": updated_data,
#             },
#             status=200,
#         )

#     except IntegrityError:
#         return JsonResponse(
#             {
#                 "success": False,
#                 "message": "A pharmacy with this email already exists.",
#                 "field": "email",
#             },
#             status=400,
#         )

#     except Exception as e:
#         return JsonResponse(
#             {"success": False, "message": "Something went wrong.", "error": str(e)},
#             status=500,
#         )


@csrf_protect
@admin_auth_required
@require_http_methods(["PUT"])
def edit_pharmacy(request, pharmacy_id):
    """
    PRODUCTION: Edit Pharmacy (Admin Only)

    - Secure (CSRF + Admin Auth)
    - PUT only
    - Accepts optional business_hours
    - Validates business_hours if provided
    - Does NOT modify password or active status (use separate endpoints)
    """
    
    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
    except Pharmacy.DoesNotExist:
        return JsonResponse({
            "success": False,
            "error": "Pharmacy not found"
        }, status=404)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse({
            "success": False,
            "error": "Invalid JSON payload"
        }, status=400)

    # Editable fields
    editable_fields = [
        "name",
        "store_address",
        "city",
        "province",
        "postal_code",
        "country",
        "phone_number",
        "email",
    ]

    # Update basic fields
    for field in editable_fields:
        if field in payload:
            value = payload[field]
            if isinstance(value, str):
                value = value.strip()
            setattr(pharmacy, field, value)

    # Handle business_hours separately (optional)
    if "business_hours" in payload:
        business_hours = payload["business_hours"]
        try:
            validate_business_hours(business_hours)
            pharmacy.business_hours = business_hours
        except ValueError as e:
            return JsonResponse({
                "success": False,
                "error": str(e)
            }, status=400)

    try:
        pharmacy.save()

        # ---- Time handling (DB=UTC, Display=Local) ----
        updated_at_utc = timezone.now()
        try:
            updated_at_local = updated_at_utc.astimezone(settings.USER_TIMEZONE)
        except Exception:
            updated_at_local = updated_at_utc

        return JsonResponse({
            "success": True,
            "message": "Pharmacy updated successfully",
            "pharmacy": {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "store_address": pharmacy.store_address,
                "city": pharmacy.city,
                "province": pharmacy.province,
                "postal_code": pharmacy.postal_code,
                "country": pharmacy.country,
                "phone_number": pharmacy.phone_number,
                "email": pharmacy.email,
                "active": pharmacy.active,
                "business_hours": pharmacy.business_hours,
                "created_at_local": timezone.localtime(
                    pharmacy.created_at,
                    settings.USER_TIMEZONE
                ).isoformat(),
                "updated_at_local": updated_at_local.isoformat(),
                "timezone": str(settings.USER_TIMEZONE),
            }
        }, status=200)

    except IntegrityError:
        return JsonResponse({
            "success": False,
            "error": "A pharmacy with this email already exists"
        }, status=400)

    except Exception as e:
        logger.exception(f"Error updating pharmacy {pharmacy_id}")
        return JsonResponse({
            "success": False,
            "error": "Internal server error",
            "details": str(e)
        }, status=500)


@require_http_methods(["PUT"])
@csrf_protect
@admin_auth_required
def edit_driver(request, driver_id):
    """
    Admin-only API to update an existing driver.
    - Partial updates supported
    - DB stores UTC
    - Responses return settings.USER_TIMEZONE
    """

    # 1️⃣ Fetch driver
    try:
        driver = Driver.objects.get(id=driver_id)
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver not found."},
            status=404,
        )

    # 2️⃣ Parse JSON payload
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

    # 3️⃣ Allowed editable fields
    editable_fields = {
        "name": str,
        "phone_number": str,
        "email": str,
        "vehicle_number": str,
        "active": bool,
        # identity_url intentionally excluded
    }

    # 4️⃣ Apply updates (only provided fields)
    for field, field_type in editable_fields.items():
        if field in data:
            value = data[field]

            if field_type is str:
                value = value.strip()
                if field == "email":
                    value = value.lower()

            setattr(driver, field, value)

    try:
        # 5️⃣ Save updates
        driver.save()

        # 6️⃣ Convert UTC → USER_TIMEZONE for response
        local_created_at = timezone.localtime(
            driver.created_at, settings.USER_TIMEZONE
        )

        updated_data = {
            "id": driver.id,
            "name": driver.name,
            "phone_number": driver.phone_number,
            "email": driver.email,
            "vehicle_number": driver.vehicle_number,
            "active": driver.active,
            "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse(
            {
                "success": True,
                "message": "Driver updated successfully.",
                "driver": updated_data,
            },
            status=200,
        )

    except IntegrityError:
        # Unique email constraint
        return JsonResponse(
            {
                "success": False,
                "message": "A driver with this email already exists.",
                "field": "email",
            },
            status=400,
        )

    except Exception:
        # Do not leak internals in prod
        return JsonResponse(
            {
                "success": False,
                "message": "Something went wrong while updating the driver.",
            },
            status=500,
        )




@csrf_protect
@admin_auth_required
@require_http_methods(["PATCH"])
def toggle_pharmacy_status(request, pharmacy_id):
    """
    PRODUCTION: Toggle / Set Pharmacy Active Status (Admin Only)

    PATCH /api/admin/pharmacies/<pharmacy_id>/status/

    Behavior:
    - If request body contains {"active": true/false} → explicitly set
    - If no body or no "active" field → toggle current value

    Security:
    - CSRF protected
    - Admin only

    Time handling:
    - Stored in UTC
    - Returned in settings.USER_TIMEZONE
    """

    user_tz = settings.USER_TIMEZONE
    now_utc = timezone.now()
    now_local = timezone.localtime(now_utc, user_tz)

    # -------------------------------------------------
    # Validate pharmacy exists
    # -------------------------------------------------
    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
    except Pharmacy.DoesNotExist:
        return JsonResponse({
            "success": False,
            "error": "Pharmacy not found"
        }, status=404)

    previous_status = pharmacy.active

    # -------------------------------------------------
    # Parse optional JSON body
    # -------------------------------------------------
    new_status = None
    try:
        if request.body:
            payload = json.loads(request.body.decode("utf-8"))
            if "active" in payload:
                new_status = bool(payload["active"])
    except json.JSONDecodeError:
        return JsonResponse({
            "success": False,
            "error": "Invalid JSON payload"
        }, status=400)

    # -------------------------------------------------
    # Apply status change
    # -------------------------------------------------
    if new_status is None:
        # Toggle
        pharmacy.active = not pharmacy.active
        action_type = "toggled"
    else:
        # Explicit set
        pharmacy.active = new_status
        action_type = "set"

    pharmacy.save(update_fields=["active"])

    # -------------------------------------------------
    # Optional audit logging (recommended)
    # -------------------------------------------------
    try:
        OrderTracking.objects.create(
            order=None,  # or use a separate AdminAudit model later
            pharmacy=pharmacy,
            step="status_change",
            performed_by="admin_panel",
            timestamp=now_utc,
            note=f"Pharmacy status {action_type}: {previous_status} → {pharmacy.active}"
        )
    except Exception:
        # Never fail the API because of audit logging
        pass

    # -------------------------------------------------
    # Response
    # -------------------------------------------------
    return JsonResponse({
        "success": True,
        "message": (
            "Pharmacy activated successfully."
            if pharmacy.active else
            "Pharmacy deactivated successfully."
        ),
        "pharmacy": {
            "id": pharmacy.id,
            "name": pharmacy.name,
            "previous_active": previous_status,
            "current_active": pharmacy.active,
        },
        "updated_at_local": now_local.isoformat(),
        "timezone": str(user_tz),
    }, status=200)


@require_http_methods(["POST", "PATCH"])
@csrf_protect
@admin_auth_required
def toggle_driver_status(request, driver_id):
    """
    Admin-only API to activate/deactivate a driver.
    - Supports explicit active flag OR toggle
    - Stores UTC in DB
    - Returns timestamps in settings.USER_TIMEZONE
    """

    # 1️⃣ Fetch driver
    try:
        driver = Driver.objects.get(id=driver_id)
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver not found."},
            status=404,
        )

    # 2️⃣ Parse JSON body (optional)
    new_status = None
    if request.body:
        try:
            data = json.loads(request.body.decode("utf-8"))
            if "active" in data:
                new_status = bool(data["active"])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse(
                {"success": False, "message": "Invalid JSON payload."},
                status=400,
            )

    # 3️⃣ Apply status change
    if new_status is not None:
        driver.active = new_status
    else:
        driver.active = not driver.active

    driver.save()

    # 4️⃣ Convert UTC → USER_TIMEZONE (for consistency)
    local_created_at = timezone.localtime(
        driver.created_at, settings.USER_TIMEZONE
    )

    return JsonResponse(
        {
            "success": True,
            "message": "Driver activated." if driver.active else "Driver deactivated.",
            "driver": {
                "id": driver.id,
                "name": driver.name,
                "active": driver.active,
                "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=200,
    )



@csrf_protect
@admin_auth_required
@require_http_methods(["POST", "PATCH"])
def reset_pharmacy_password(request, pharmacy_id):
    """
    PRODUCTION: Reset Pharmacy Password (Admin Only)

    POST / PATCH /api/pharmacy/<id>/reset-password/

    - Admin only
    - CSRF protected
    - Resets password to system default
    - Password hashing handled by model save()
    """

    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {
                "success": False,
                "error": "Pharmacy not found."
            },
            status=404,
        )

    # 🔐 Reset password to default (hashed automatically in model.save)
    DEFAULT_PASSWORD = "123456"
    pharmacy.password = DEFAULT_PASSWORD
    pharmacy.save(update_fields=["password"])

    return JsonResponse(
        {
            "success": True,
            "message": "Pharmacy password reset successfully.",
            "pharmacy": {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "email": pharmacy.email,
                "active": pharmacy.active,
                "updated_at_local": timezone.localtime(
                    pharmacy.updated_at if hasattr(pharmacy, "updated_at") else timezone.now(),
                    settings.USER_TIMEZONE
                ).isoformat(),
            },
            "timezone": str(settings.USER_TIMEZONE),
        },
        status=200,
    )


# @csrf_exempt
# def reset_driver_password(request, driver_id):
#     if request.method not in ["POST", "PATCH"]:
#         return JsonResponse(
#             {"success": False, "message": "Only POST or PATCH method is allowed."},
#             status=405,
#         )

#     try:
#         driver = Driver.objects.get(id=driver_id)
#     except Driver.DoesNotExist:
#         return JsonResponse(
#             {"success": False, "message": "Driver not found."},
#             status=404,
#         )

#     # Reset password to default — model will hash it automatically
#     driver.password = "123456"
#     driver.save()

#     return JsonResponse(
#         {
#             "success": True,
#             "message": "Password reset successfully.",
#             "driver": {
#                 "id": driver.id,
#                 "name": driver.name,
#                 "email": driver.email,
#                 "active": driver.active,
#             },
#         },
#         status=200,
#     )


@require_http_methods(["POST", "PATCH"])
@csrf_protect
@admin_auth_required
def reset_driver_password(request, driver_id):
    """
    Admin-only API to reset a driver's password.
    - Resets password to default
    - Password hashing handled by model save()
    - DB stores UTC, responses use settings.USER_TIMEZONE
    """

    # 1️⃣ Fetch driver
    try:
        driver = Driver.objects.get(id=driver_id)
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver not found."},
            status=404,
        )

    # 2️⃣ Reset password (model hashes automatically)
    driver.password = "123456"
    driver.save()

    # 3️⃣ Convert UTC → USER_TIMEZONE for response consistency
    local_created_at = timezone.localtime(
        driver.created_at, settings.USER_TIMEZONE
    )

    return JsonResponse(
        {
            "success": True,
            "message": "Password reset successfully.",
            "driver": {
                "id": driver.id,
                "name": driver.name,
                "email": driver.email,
                "active": driver.active,
                "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=200,
    )




@require_http_methods(["GET"])
@csrf_protect
@admin_auth_required
def get_all_pharmacy_invoices(request):
    """
    Admin-only: Returns pharmacy invoices with pharmacy details.
    - DB stores UTC
    - Responses use settings.USER_TIMEZONE (created_at)
    - Supports pagination + basic filtering
        Query params:
          - limit (default 100, max 500)
          - offset (default 0)
          - status (optional: generated|paid|past_due)
          - pharmacy_id (optional int)
    """

    # ---------- Query params (safe defaults) ----------
    try:
        limit = int(request.GET.get("limit", 100))
    except ValueError:
        return JsonResponse(
            {"success": False, "message": "Invalid limit. Must be an integer."},
            status=400,
        )

    try:
        offset = int(request.GET.get("offset", 0))
    except ValueError:
        return JsonResponse(
            {"success": False, "message": "Invalid offset. Must be an integer."},
            status=400,
        )

    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    status_filter = request.GET.get("status")
    pharmacy_id = request.GET.get("pharmacy_id")

    # ---------- Build queryset ----------
    try:
        invoices_qs = Invoice.objects.select_related("pharmacy").order_by("-created_at")

        if status_filter:
            allowed_statuses = {s for (s, _) in Invoice.STATUS_CHOICES}
            if status_filter not in allowed_statuses:
                return JsonResponse(
                    {
                        "success": False,
                        "message": "Invalid status filter.",
                        "allowed": sorted(list(allowed_statuses)),
                    },
                    status=400,
                )
            invoices_qs = invoices_qs.filter(status=status_filter)

        if pharmacy_id:
            try:
                pharmacy_id_int = int(pharmacy_id)
            except ValueError:
                return JsonResponse(
                    {
                        "success": False,
                        "message": "Invalid pharmacy_id. Must be an integer.",
                    },
                    status=400,
                )
            invoices_qs = invoices_qs.filter(pharmacy_id=pharmacy_id_int)

        total_count = invoices_qs.count()

        invoices_page = invoices_qs[offset : offset + limit]

        invoices_list = []
        for inv in invoices_page:
            # Convert UTC -> USER_TIMEZONE for response consistency
            local_created_at = timezone.localtime(inv.created_at, settings.USER_TIMEZONE)

            # Money: avoid float rounding issues; return as string (recommended)
            total_amount_str = (
                str(inv.total_amount) if isinstance(inv.total_amount, Decimal) else str(inv.total_amount)
            )

            invoices_list.append(
                {
                    "invoice_id": inv.id,
                    "pharmacy_id": inv.pharmacy.id,
                    "pharmacy_name": inv.pharmacy.name,
                    "period": {
                        "start_date": inv.start_date.isoformat(),
                        "end_date": inv.end_date.isoformat(),
                    },
                    "total_orders": inv.total_orders,
                    "total_amount": total_amount_str,
                    "due_date": inv.due_date.isoformat(),
                    "status": inv.status,
                    "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "pdf_url": inv.pdf_url,
                    "stripe_payment_id": inv.stripe_payment_id,
                }
            )

        return JsonResponse(
            {
                "success": True,
                "invoices": invoices_list,
                "count": len(invoices_list),
                "total_count": total_count,
                "limit": limit,
                "offset": offset,
            },
            status=200,
        )

    except Exception:
        # Do not leak internals in production
        return JsonResponse(
            {"success": False, "message": "Something went wrong while fetching invoices."},
            status=500,
        )


@require_http_methods(["POST"])
@csrf_protect
@admin_auth_required
def mark_pharmacy_invoice_paid(request, invoice_id):
    """
    Admin-only API to mark a pharmacy invoice as PAID
    and store the Stripe payment reference ID.
    """

    # 1️⃣ Fetch invoice
    try:
        invoice = Invoice.objects.select_related("pharmacy").get(id=invoice_id)
    except Invoice.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Invoice not found."},
            status=404,
        )

    # 2️⃣ Parse JSON payload
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

    stripe_payment_id = data.get("stripe_payment_id")

    if not stripe_payment_id:
        return JsonResponse(
            {
                "success": False,
                "message": "stripe_payment_id is required.",
            },
            status=400,
        )

    # 3️⃣ Prevent double payment
    if invoice.status == "paid":
        return JsonResponse(
            {
                "success": False,
                "message": "Invoice is already marked as paid.",
            },
            status=400,
        )

    # 4️⃣ Update invoice
    invoice.status = "paid"
    invoice.stripe_payment_id = stripe_payment_id.strip()
    invoice.save()

    # 5️⃣ Convert UTC → USER_TIMEZONE for response
    local_created_at = timezone.localtime(
        invoice.created_at, settings.USER_TIMEZONE
    )

    return JsonResponse(
        {
            "success": True,
            "message": "Invoice marked as paid.",
            "invoice": {
                "invoice_id": invoice.id,
                "pharmacy_id": invoice.pharmacy.id,
                "pharmacy_name": invoice.pharmacy.name,
                "status": invoice.status,
                "stripe_payment_id": invoice.stripe_payment_id,
                "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=200,
    )


@require_http_methods(["GET"])
@csrf_protect
@admin_auth_required
def get_all_driver_invoices(request):
    """
    Admin-only: Returns all driver invoices.
    - DB stores UTC
    - API responses use settings.USER_TIMEZONE
    - Response format intentionally unchanged
    """

    try:
        invoices = (
            DriverInvoice.objects
            .select_related("driver")
            .order_by("-created_at")
        )

        invoice_list = []
        for inv in invoices:
            # Convert UTC -> USER_TIMEZONE for response
            local_created_at = timezone.localtime(
                inv.created_at,
                settings.USER_TIMEZONE
            )

            invoice_list.append({
                "invoice_id": inv.id,
                "driver_id": inv.driver.id,
                "driver_name": inv.driver.name,
                "driver_email": inv.driver.email,
                "driver_phone_number": inv.driver.phone_number,

                # Period
                "start_date": str(inv.start_date),
                "end_date": str(inv.end_date),

                # Invoice stats
                "total_deliveries": inv.total_deliveries,
                "total_amount": float(inv.total_amount),
                "due_date": str(inv.due_date),

                # Status + PDF
                "status": inv.status,
                "pdf_url": inv.pdf_url,
                "payment_reference_id" : inv.payment_reference_id,

                # Meta
                "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

        return JsonResponse(
            {
                "success": True,
                "invoices": invoice_list,
            },
            status=200
        )

    except Exception:
        # Do not leak internal errors in production
        return JsonResponse(
            {
                "success": False,
                "message": "Something went wrong while fetching driver invoices.",
            },
            status=500
        )


@require_http_methods(["POST"])
@csrf_protect
@admin_auth_required
def mark_driver_invoice_paid(request, invoice_id):
    """
    Admin-only API to mark a driver invoice as PAID
    and store the payment reference ID.
    """

    # 1️⃣ Fetch invoice
    try:
        invoice = DriverInvoice.objects.select_related("driver").get(id=invoice_id)
    except DriverInvoice.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver invoice not found."},
            status=404,
        )

    # 2️⃣ Parse JSON payload
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

    payment_reference_id = data.get("payment_reference_id")

    if not payment_reference_id:
        return JsonResponse(
            {
                "success": False,
                "message": "payment_reference_id is required.",
            },
            status=400,
        )

    # 3️⃣ Prevent double payment
    if invoice.status == "paid":
        return JsonResponse(
            {
                "success": False,
                "message": "Invoice is already marked as paid.",
            },
            status=400,
        )

    # 4️⃣ Update invoice
    invoice.status = "paid"
    invoice.payment_reference_id = payment_reference_id.strip()
    invoice.save()

    # 5️⃣ Convert UTC → USER_TIMEZONE
    local_created_at = timezone.localtime(
        invoice.created_at, settings.USER_TIMEZONE
    )

    return JsonResponse(
        {
            "success": True,
            "message": "Driver invoice marked as paid.",
            "invoice": {
                "invoice_id": invoice.id,
                "driver_id": invoice.driver.id,
                "driver_name": invoice.driver.name,
                "status": invoice.status,
                "payment_reference_id": invoice.payment_reference_id,
                "created_at": local_created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=200,
    )




@require_http_methods(["GET"])
@csrf_protect
@admin_auth_required
def get_payment_alerts(request):
    """
    Returns all payment alerts from:
    - Pharmacy Invoices (past_due or due soon)
    - Driver Invoices (generated & due soon or overdue)
    """

    try:
        # ✅ Use USER_TIMEZONE for business-correct date logic
        today = timezone.localtime(
            timezone.now(), settings.USER_TIMEZONE
        ).date()

        upcoming_limit = today + timedelta(days=3)

        alerts = []

        # 🔶 1. Pharmacy Invoices — Past Due
        pharmacy_past_due = Invoice.objects.filter(status="past_due")
        for inv in pharmacy_past_due:
            alerts.append({
                "type": "pharmacy",
                "invoice_id": inv.id,
                "entity_name": inv.pharmacy.name,
                "total_amount": float(inv.total_amount),
                "status": inv.status,
                "due_date": str(inv.due_date),
                "days_left": (inv.due_date - today).days,
                "pdf_url": inv.pdf_url,
            })

        # 🔶 2. Pharmacy Invoices — Due Soon (within 3 days)
        pharmacy_due_soon = Invoice.objects.filter(
            status="generated",
            due_date__lte=upcoming_limit,
            due_date__gte=today
        )
        for inv in pharmacy_due_soon:
            alerts.append({
                "type": "pharmacy",
                "invoice_id": inv.id,
                "entity_name": inv.pharmacy.name,
                "total_amount": float(inv.total_amount),
                "status": inv.status,
                "due_date": str(inv.due_date),
                "days_left": (inv.due_date - today).days,
                "pdf_url": inv.pdf_url,
            })

        # 🔶 3. Driver Invoices — Overdue
        driver_overdue = DriverInvoice.objects.filter(
            status="generated",
            due_date__lt=today
        )
        for inv in driver_overdue:
            alerts.append({
                "type": "driver",
                "invoice_id": inv.id,
                "entity_name": inv.driver.name,
                "total_amount": float(inv.total_amount),
                "status": "past_due",  # business-level status
                "due_date": str(inv.due_date),
                "days_left": (inv.due_date - today).days,
                "pdf_url": inv.pdf_url,
            })

        # 🔶 4. Driver Invoices — Due Soon (within 3 days)
        driver_due_soon = DriverInvoice.objects.filter(
            status="generated",
            due_date__lte=upcoming_limit,
            due_date__gte=today
        )
        for inv in driver_due_soon:
            alerts.append({
                "type": "driver",
                "invoice_id": inv.id,
                "entity_name": inv.driver.name,
                "total_amount": float(inv.total_amount),
                "status": inv.status,
                "due_date": str(inv.due_date),
                "days_left": (inv.due_date - today).days,
                "pdf_url": inv.pdf_url,
            })

        # 🔽 Sort by urgency (overdue first)
        alerts.sort(key=lambda x: x["days_left"])

        return JsonResponse(
            {
                "success": True,
                "count": len(alerts),
                "alerts": alerts
            },
            status=200,
        )

    except Exception as e:
        return JsonResponse(
            {
                "success": False,
                "error": str(e)
            },
            status=500,
        )


@require_http_methods(["GET"])
@csrf_protect
@admin_auth_required
def get_monthly_financials(request):
    """
    Monthly financial summary (USER_TIMEZONE):
    - revenue_this_month
    - driver_payout_this_month (60%)
    - net_commission (40%)
    """

    try:
        # ✅ Local-time month boundaries
        now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
        month_start_local = now_local.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )

        if month_start_local.month == 12:
            next_month_start_local = month_start_local.replace(
                year=month_start_local.year + 1, month=1
            )
        else:
            next_month_start_local = month_start_local.replace(
                month=month_start_local.month + 1
            )

        # Convert to UTC for DB filtering
        month_start_utc = month_start_local.astimezone(timezone.utc)
        next_month_start_utc = next_month_start_local.astimezone(timezone.utc)

        # 1️⃣ Revenue — delivered orders THIS MONTH
        revenue = (
            DeliveryOrder.objects.filter(
                status="delivered",
                delivered_at__isnull=False,
                delivered_at__gte=month_start_utc,
                delivered_at__lt=next_month_start_utc,
            )
            .aggregate(total=Sum("rate"))["total"]
            or 0
        )

        revenue_float = float(revenue)

        # 2️⃣ Commission & payout (policy-based)
        company_commission_rate = float(
            getattr(settings, "DRIVER_COMMISSION_RATE", 0.40)
        )
        driver_payout_rate = 1 - company_commission_rate

        driver_payout_value = revenue_float * driver_payout_rate
        net_commission_value = revenue_float * company_commission_rate

        return JsonResponse(
            {
                "success": True,
                "financials": {
                    "revenue_this_month": revenue_float,
                    "driver_payout_this_month": driver_payout_value,
                    "net_commission": {
                        "value": net_commission_value,
                        "percentage_of_revenue": company_commission_rate * 100,
                    },
                },
            },
            status=200,
        )

    except Exception:
        # Prod-safe error
        return JsonResponse(
            {
                "success": False,
                "error": "Something went wrong while calculating financial metrics."
            },
            status=500,
        )


@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def get_contact_ticket_details(request, ticket_id=None):
    """
    Admin-only API.

    - If ticket_id is None: returns ALL tickets (latest first)
    - If ticket_id is provided: returns SINGLE ticket

    Timezone rule:
    - DB stores UTC
    - Responses return timestamps in settings.USER_TIMEZONE
    """
    try:
        def fmt_dt(dt):
            if not dt:
                return None
            # ✅ Convert to local time for response
            local_dt = timezone.localtime(dt, settings.USER_TIMEZONE)
            return local_dt.strftime("%Y-%m-%d %H:%M:%S")

        def build_pharmacy_info(pharmacy):
            """Build comprehensive pharmacy information"""
            return {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "email": pharmacy.email,
                "phone_number": pharmacy.phone_number,
                "store_address": pharmacy.store_address,
                "city": pharmacy.city,
                "province": pharmacy.province,
                "postal_code": pharmacy.postal_code,
                "country": pharmacy.country,
                "active": pharmacy.active,
                "business_hours": pharmacy.business_hours,
                "is_open_now": pharmacy.is_open_now(),
                "created_at": fmt_dt(pharmacy.created_at),
                # Statistics
                "total_orders": pharmacy.orders.count(),
                "pending_invoices": pharmacy.invoices.filter(status__in=['generated', 'past_due']).count(),
                "total_contact_tickets": pharmacy.contacts.count(),
            }

        def build_driver_info(driver):
            """Build comprehensive driver information"""
            return {
                "id": driver.id,
                "name": driver.name,
                "email": driver.email,
                "phone_number": driver.phone_number,
                "vehicle_number": driver.vehicle_number,
                "active": driver.active,
                "identity_url": driver.identity_url,
                "created_at": fmt_dt(driver.created_at),
                # Statistics
                "total_deliveries": driver.orders.filter(status='delivered').count(),
                "pending_orders": driver.orders.filter(status__in=['accepted', 'inTransit', 'picked_up']).count(),
                "total_invoices": driver.invoices.count(),
                "total_contact_tickets": driver.contacts.count(),
            }

        # --------------------------------------------------
        # 1️⃣ CASE: RETURN ALL TICKETS
        # --------------------------------------------------
        if ticket_id is None:
            tickets = (
                ContactAdmin.objects
                .select_related("pharmacy", "driver")
                .all()
                .order_by("-created_at")
            )

            ticket_list = []

            for t in tickets:
                sender_type = "pharmacy" if t.pharmacy else "driver" if t.driver else "unknown"

                sender_info = None
                if t.pharmacy:
                    sender_info = build_pharmacy_info(t.pharmacy)
                elif t.driver:
                    sender_info = build_driver_info(t.driver)

                ticket_list.append({
                    "ticket_id": t.id,
                    "subject_key": t.subject,
                    "subject": t.get_subject_display() if t.subject != "other" else t.other_subject,
                    "status": t.status,
                    "message": t.message,
                    "admin_response": t.admin_response,
                    "sender_type": sender_type,
                    "sender": sender_info,
                    "created_at": fmt_dt(t.created_at),
                    "updated_at": fmt_dt(t.updated_at),
                })

            return JsonResponse({"success": True, "tickets": ticket_list}, status=200)

        # --------------------------------------------------
        # 2️⃣ CASE: RETURN SINGLE TICKET
        # --------------------------------------------------
        ticket = (
            ContactAdmin.objects
            .select_related("pharmacy", "driver")
            .get(id=ticket_id)
        )

        sender_type = "pharmacy" if ticket.pharmacy else "driver" if ticket.driver else "unknown"

        # sender info details
        if ticket.pharmacy:
            sender_info = build_pharmacy_info(ticket.pharmacy)
        elif ticket.driver:
            sender_info = build_driver_info(ticket.driver)
        else:
            sender_info = None

        ticket_data = {
            "ticket_id": ticket.id,
            "subject_key": ticket.subject,
            "subject": ticket.get_subject_display() if ticket.subject != "other" else ticket.other_subject,
            "status": ticket.status,
            "message": ticket.message,
            "admin_response": ticket.admin_response,
            "sender_type": sender_type,
            "sender": sender_info,
            "created_at": fmt_dt(ticket.created_at),
            "updated_at": fmt_dt(ticket.updated_at),
        }

        return JsonResponse({"success": True, "ticket": ticket_data}, status=200)

    except ContactAdmin.DoesNotExist:
        return JsonResponse({"success": False, "message": "Ticket not found"}, status=404)

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



# @csrf_exempt
# def update_ticket_status(request, ticket_id):
#     """
#     Update the status of a ContactAdmin ticket.

#     Expects JSON body:
#     {
#         "status": "pending" | "in_progress" | "resolved"
#     }
#     """
#     if request.method not in ["POST", "PATCH"]:
#         return JsonResponse(
#             {"success": False, "message": "Only POST or PATCH method is allowed."},
#             status=405,
#         )

#     # 1️⃣ Fetch ticket
#     try:
#         ticket = ContactAdmin.objects.get(id=ticket_id)
#     except ContactAdmin.DoesNotExist:
#         return JsonResponse(
#             {"success": False, "message": "Ticket not found."},
#             status=404,
#         )

#     # 2️⃣ Parse JSON body
#     try:
#         data = json.loads(request.body.decode("utf-8"))
#     except json.JSONDecodeError:
#         return JsonResponse(
#             {"success": False, "message": "Invalid JSON payload."},
#             status=400,
#         )

#     new_status = data.get("status")
#     if not new_status:
#         return JsonResponse(
#             {"success": False, "message": "Missing 'status' in request body."},
#             status=400,
#         )

#     # 3️⃣ Validate status
#     valid_statuses = [choice[0] for choice in ContactAdmin.STATUS_CHOICES]
#     if new_status not in valid_statuses:
#         return JsonResponse(
#             {
#                 "success": False,
#                 "message": "Invalid status value.",
#                 "allowed_values": valid_statuses,
#             },
#             status=400,
#         )

#     # 4️⃣ Update & save
#     old_status = ticket.status
#     ticket.status = new_status
#     ticket.save()

#     # 5️⃣ Send email notification to ticket raiser
#     try:
#         # Get ticket raiser info
#         user_email = None
#         user_name = None
#         user_type = None
        
#         if ticket.pharmacy:
#             user_email = ticket.pharmacy.email
#             user_name = ticket.pharmacy.name
#             user_type = "Pharmacy"
#         elif ticket.driver:
#             user_email = ticket.driver.email
#             user_name = ticket.driver.name
#             user_type = "Driver"
        
#         if user_email:
#             brand_primary = settings.BRAND_COLORS['primary']
#             brand_primary_dark = settings.BRAND_COLORS['primary_dark']
#             brand_accent = settings.BRAND_COLORS['accent']
#             now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
#             logo_url = settings.LOGO_URL
            
#             # Format subject for display
#             subject_display = ticket.other_subject if ticket.subject == 'other' else ticket.get_subject_display()
            
#             # Status color mapping
#             status_colors = {
#                 'pending': '#f59e0b',
#                 'in_progress': '#3b82f6',
#                 'resolved': '#10b981'
#             }
#             status_bg_colors = {
#                 'pending': '#fff7ed',
#                 'in_progress': '#eff6ff',
#                 'resolved': '#f0fdf4'
#             }
#             status_text = new_status.replace('_', ' ').title()
#             status_color = status_colors.get(new_status, '#6b7280')
#             status_bg = status_bg_colors.get(new_status, '#f8fafc')

#             html = f"""\
# <!doctype html>
# <html lang="en">
#   <head>
#     <meta charset="utf-8">
#     <title>Ticket Status Updated • {settings.COMPANY_OPERATING_NAME}</title>
#     <meta name="viewport" content="width=device-width, initial-scale=1">
#     <style>
#       @media (prefers-color-scheme: dark) {{
#         body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
#         .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
#         .muted {{ color: #94a3b8 !important; }}
#       }}
#     </style>
#   </head>
#   <body style="margin:0;padding:0;background:#f4f7f9;">
#     <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
#       Your support ticket status has been updated.
#     </div>

#     <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
#       <tr>
#         <td align="center">
#           <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
#             <tr>
#               <td style="background:{brand_primary};padding:18px 20px;">
#                 <table width="100%" cellspacing="0" cellpadding="0" border="0">
#                   <tr>
#                     <td align="left">
#                       <img src="{logo_url}"
#                            alt="{settings.COMPANY_OPERATING_NAME}"
#                            width="64"
#                            height="64"
#                            style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
#                     </td>
#                     <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
#                       Ticket Status Updated
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>

#             <tr>
#               <td style="padding:28px 24px 6px;">
#                 <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                   Hi {user_name}, your ticket status changed
#                 </h1>
#                 <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
#                   Your support ticket <strong>#{ticket.id}</strong> status has been updated by our admin team.
#                 </p>

#                 <div style="margin:18px 0;background:{status_bg};border:1px solid {status_color};border-radius:12px;padding:16px 18px;">
#                   <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                     Ticket Status:
#                   </p>
#                   <p style="margin:0;font:700 18px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{status_color};text-transform:uppercase;">
#                     {status_text}
#                   </p>
#                 </div>

#                 <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
#                   <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
#                     <tr style="background:#f1f5f9;">
#                       <td style="padding:12px 18px;color:#64748b;font-weight:600;">Ticket ID</td>
#                       <td style="padding:12px 18px;color:#0f172a;font-weight:500;">#{ticket.id}</td>
#                     </tr>
#                     <tr>
#                       <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Subject</td>
#                       <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{subject_display}</td>
#                     </tr>
#                     <tr style="background:#f1f5f9;">
#                       <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Updated On</td>
#                       <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
#                     </tr>
#                   </table>
#                 </div>

#                 <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
#                 <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
#                   You'll receive another notification when our team responds to your ticket. If you have additional questions, login to the portal and raise another Support Ticket by contacting the Admin.
#                 </p>
#               </td>
#             </tr>

#             <tr>
#               <td style="padding:0 24px 24px;">
#                 <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
#                   <tr>
#                     <td style="padding:12px 16px;">
#                       <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
#                         Thank you for your patience — we're working on your request.
#                       </p>
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>

#           </table>

#           <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
#             © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
#           </p>
#         </td>
#       </tr>
#     </table>
#   </body>
# </html>
# """
#             text = (
#                 f"Ticket Status Updated - {settings.COMPANY_OPERATING_NAME}\n\n"
#                 f"Hi {user_name},\n\n"
#                 f"Your support ticket #{ticket.id} status has been updated.\n\n"
#                 f"Ticket ID: #{ticket.id}\n"
#                 f"Subject: {subject_display}\n"
#                 f"New Status: {status_text}\n"
#                 f"Updated On: {now_str}\n\n"
#                 "You'll receive another notification when our team responds to your ticket.\n"
#             )

#             _send_html_email_admin_office(
#                 subject=f"Ticket #{ticket.id} Status Updated: {status_text}",
#                 to_email=user_email,
#                 html=html,
#                 text_fallback=text,
#             )
#     except Exception:
#         logger.exception("Failed to send ticket status update email")

#     # 6️⃣ Build response
#     return JsonResponse(
#         {
#             "success": True,
#             "message": "Ticket status updated successfully.",
#             "ticket": {
#                 "ticket_id": ticket.id,
#                 "status": ticket.status,
#                 "subject_key": ticket.subject,
#                 "subject": ticket.get_subject_display() if ticket.subject != "other" else ticket.other_subject,
#                 "updated_at": ticket.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
#             },
#         },
#         status=200,
#     )


@csrf_protect
@admin_auth_required
@require_http_methods(["POST", "PATCH"])
def update_ticket_status(request, ticket_id):
    """
    Admin-only API to update the status of a ContactAdmin ticket.

    Expects JSON body:
    {
        "status": "pending" | "in_progress" | "resolved"
    }
    
    Timezone rule:
    - DB stores UTC
    - Email timestamps use settings.USER_TIMEZONE
    - Response timestamps use settings.USER_TIMEZONE
    """
    try:
        # 1️⃣ Fetch ticket
        try:
            ticket = ContactAdmin.objects.select_related("pharmacy", "driver").get(id=ticket_id)
        except ContactAdmin.DoesNotExist:
            return JsonResponse(
                {"success": False, "message": "Ticket not found."},
                status=404,
            )

        # 2️⃣ Parse JSON body
        try:
            data = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "message": "Invalid JSON payload."},
                status=400,
            )

        new_status = data.get("status")
        if not new_status:
            return JsonResponse(
                {"success": False, "message": "Missing 'status' in request body."},
                status=400,
            )

        # 3️⃣ Validate status
        valid_statuses = [choice[0] for choice in ContactAdmin.STATUS_CHOICES]
        if new_status not in valid_statuses:
            return JsonResponse(
                {
                    "success": False,
                    "message": "Invalid status value.",
                    "allowed_values": valid_statuses,
                },
                status=400,
            )

        # 4️⃣ Update & save
        old_status = ticket.status
        ticket.status = new_status
        ticket.save()

        # 5️⃣ Send email notification to ticket raiser
        try:
            # Get ticket raiser info
            user_email = None
            user_name = None
            user_type = None
            
            if ticket.pharmacy:
                user_email = ticket.pharmacy.email
                user_name = ticket.pharmacy.name
                user_type = "Pharmacy"
            elif ticket.driver:
                user_email = ticket.driver.email
                user_name = ticket.driver.name
                user_type = "Driver"
            
            if user_email:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                
                # ✅ Convert UTC to local timezone for email display
                now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                
                logo_url = settings.LOGO_URL
                
                # Format subject for display
                subject_display = ticket.other_subject if ticket.subject == 'other' else ticket.get_subject_display()
                
                # Status color mapping
                status_colors = {
                    'pending': '#f59e0b',
                    'in_progress': '#3b82f6',
                    'resolved': '#10b981'
                }
                status_bg_colors = {
                    'pending': '#fff7ed',
                    'in_progress': '#eff6ff',
                    'resolved': '#f0fdf4'
                }
                status_text = new_status.replace('_', ' ').title()
                status_color = status_colors.get(new_status, '#6b7280')
                status_bg = status_bg_colors.get(new_status, '#f8fafc')

                html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Ticket Status Updated • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your support ticket status has been updated.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Ticket Status Updated
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {user_name}, your ticket status changed
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Your support ticket <strong>#{ticket.id}</strong> status has been updated by our admin team.
                </p>

                <div style="margin:18px 0;background:{status_bg};border:1px solid {status_color};border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    Ticket Status:
                  </p>
                  <p style="margin:0;font:700 18px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{status_color};text-transform:uppercase;">
                    {status_text}
                  </p>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Ticket ID</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">#{ticket.id}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Subject</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{subject_display}</td>
                    </tr>
                    <tr style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Updated On</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
                    </tr>
                  </table>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  You'll receive another notification when our team responds to your ticket. If you have additional questions, login to the portal and raise another Support Ticket by contacting the Admin.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for your patience — we're working on your request.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Ticket Status Updated - {settings.COMPANY_OPERATING_NAME}\n\n"
                    f"Hi {user_name},\n\n"
                    f"Your support ticket #{ticket.id} status has been updated.\n\n"
                    f"Ticket ID: #{ticket.id}\n"
                    f"Subject: {subject_display}\n"
                    f"New Status: {status_text}\n"
                    f"Updated On: {now_str}\n\n"
                    "You'll receive another notification when our team responds to your ticket.\n"
                )

                _send_html_email_admin_office(
                    subject=f"Ticket #{ticket.id} Status Updated: {status_text}",
                    to_email=user_email,
                    html=html,
                    text_fallback=text,
                )
        except Exception:
            logger.exception("Failed to send ticket status update email")

        # 6️⃣ Build response with local timezone
        def fmt_dt(dt):
            if not dt:
                return None
            # ✅ Convert to local time for response
            local_dt = timezone.localtime(dt, settings.USER_TIMEZONE)
            return local_dt.strftime("%Y-%m-%d %H:%M:%S")

        return JsonResponse(
            {
                "success": True,
                "message": "Ticket status updated successfully.",
                "ticket": {
                    "ticket_id": ticket.id,
                    "status": ticket.status,
                    "subject_key": ticket.subject,
                    "subject": ticket.get_subject_display() if ticket.subject != "other" else ticket.other_subject,
                    "updated_at": fmt_dt(ticket.updated_at),
                },
            },
            status=200,
        )

    except Exception as e:
        logger.exception("Error updating ticket status")
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500
        )


# @csrf_exempt
# def add_admin_response(request, ticket_id):
#     """
#     Adds an admin response to a ticket.
#     Automatically sets the status to 'resolved' if not already resolved.

#     Expected JSON body:
#     {
#         "admin_response": "Your issue has been resolved..."
#     }
#     """
#     if request.method not in ["POST", "PATCH"]:
#         return JsonResponse(
#             {"success": False, "message": "Only POST or PATCH allowed."},
#             status=405
#         )

#     # 1️⃣ Fetch ticket
#     try:
#         ticket = ContactAdmin.objects.get(id=ticket_id)
#     except ContactAdmin.DoesNotExist:
#         return JsonResponse(
#             {"success": False, "message": "Ticket not found."},
#             status=404
#         )

#     # 2️⃣ Parse JSON
#     try:
#         data = json.loads(request.body.decode("utf-8"))
#     except json.JSONDecodeError:
#         return JsonResponse(
#             {"success": False, "message": "Invalid JSON payload."},
#             status=400
#         )

#     admin_response = data.get("admin_response")
#     if not admin_response:
#         return JsonResponse(
#             {"success": False, "message": "Missing 'admin_response'."},
#             status=400
#         )

#     # 3️⃣ Update fields
#     ticket.admin_response = admin_response

#     # Auto-resolve if not resolved
#     if ticket.status != "resolved":
#         ticket.status = "resolved"

#     ticket.save()

#     # 4️⃣ Send email notification to ticket raiser
#     try:
#         # Get ticket raiser info
#         user_email = None
#         user_name = None
#         user_type = None
        
#         if ticket.pharmacy:
#             user_email = ticket.pharmacy.email
#             user_name = ticket.pharmacy.name
#             user_type = "Pharmacy"
#         elif ticket.driver:
#             user_email = ticket.driver.email
#             user_name = ticket.driver.name
#             user_type = "Driver"
        
#         if user_email:
#             brand_primary = settings.BRAND_COLORS['primary']
#             brand_primary_dark = settings.BRAND_COLORS['primary_dark']
#             brand_accent = settings.BRAND_COLORS['accent']
#             now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
#             logo_url = settings.LOGO_URL
            
#             # Format subject for display
#             subject_display = ticket.other_subject if ticket.subject == 'other' else ticket.get_subject_display()
            
#             # Truncate original message for context (first 100 chars)
#             message_context = ticket.message[:100] + "..." if len(ticket.message) > 100 else ticket.message

#             html = f"""\
# <!doctype html>
# <html lang="en">
#   <head>
#     <meta charset="utf-8">
#     <title>Admin Response • {settings.COMPANY_OPERATING_NAME}</title>
#     <meta name="viewport" content="width=device-width, initial-scale=1">
#     <style>
#       @media (prefers-color-scheme: dark) {{
#         body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
#         .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
#         .muted {{ color: #94a3b8 !important; }}
#       }}
#     </style>
#   </head>
#   <body style="margin:0;padding:0;background:#f4f7f9;">
#     <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
#       Admin response received for your support ticket.
#     </div>

#     <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
#       <tr>
#         <td align="center">
#           <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
#             <tr>
#               <td style="background:{brand_primary};padding:18px 20px;">
#                 <table width="100%" cellspacing="0" cellpadding="0" border="0">
#                   <tr>
#                     <td align="left">
#                       <img src="{logo_url}"
#                            alt="{settings.COMPANY_OPERATING_NAME}"
#                            width="64"
#                            height="64"
#                            style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
#                     </td>
#                     <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
#                       Admin Response Received
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>

#             <tr>
#               <td style="padding:28px 24px 6px;">
#                 <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                   Hi {user_name}, we've responded to your ticket ✓
#                 </h1>
#                 <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
#                   Our admin team has reviewed and responded to your support ticket <strong>#{ticket.id}</strong>.
#                 </p>

#                 <div style="margin:18px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:16px 18px;">
#                   <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
#                     ✓ Ticket Status: <span style="font-weight:700;">RESOLVED</span>
#                   </p>
#                 </div>

#                 <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
#                   <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
#                     <tr style="background:#f1f5f9;">
#                       <td style="padding:12px 18px;color:#64748b;font-weight:600;">Ticket ID</td>
#                       <td style="padding:12px 18px;color:#0f172a;font-weight:500;">#{ticket.id}</td>
#                     </tr>
#                     <tr>
#                       <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Subject</td>
#                       <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{subject_display}</td>
#                     </tr>
#                     <tr style="background:#f1f5f9;">
#                       <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Responded On</td>
#                       <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
#                     </tr>
#                   </table>
#                 </div>

#                 <div style="margin:20px 0;background:#fffbeb;border-left:3px solid {brand_accent};border-radius:8px;padding:16px 18px;">
#                   <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
#                     YOUR ORIGINAL MESSAGE:
#                   </p>
#                   <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#451a03;">
#                     {message_context}
#                   </p>
#                 </div>

#                 <div style="margin:20px 0;background:#f0fdfa;border-left:3px solid {brand_primary};border-radius:8px;padding:16px 18px;">
#                   <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                     ADMIN RESPONSE:
#                   </p>
#                   <p style="margin:0;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;white-space:pre-wrap;">
# {admin_response}
#                   </p>
#                 </div>

#                 <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
#                 <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
#                   If you have further questions or need additional assistance, please login to the portal and raise another Support Ticket by mentioning current Ticket ID. <strong>#{ticket.id}</strong>.
#                 </p>
#               </td>
#             </tr>

#             <tr>
#               <td style="padding:0 24px 24px;">
#                 <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
#                   <tr>
#                     <td style="padding:12px 16px;">
#                       <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
#                         Thank you for contacting {settings.COMPANY_OPERATING_NAME} support. We're here to help!
#                       </p>
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>

#           </table>

#           <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
#             © {timezone.now().year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
#           </p>
#         </td>
#       </tr>
#     </table>
#   </body>
# </html>
# """
#             text = (
#                 f"Admin Response Received - {settings.COMPANY_OPERATING_NAME}\n\n"
#                 f"Hi {user_name},\n\n"
#                 f"Our admin team has responded to your support ticket #{ticket.id}.\n\n"
#                 f"Ticket ID: #{ticket.id}\n"
#                 f"Subject: {subject_display}\n"
#                 f"Status: RESOLVED\n"
#                 f"Responded On: {now_str}\n\n"
#                 "YOUR ORIGINAL MESSAGE:\n"
#                 f"{message_context}\n\n"
#                 "ADMIN RESPONSE:\n"
#                 f"{admin_response}\n\n"
#                 f"If you have further questions, reply to this email with your ticket ID #{ticket.id}.\n"
#             )

#             _send_html_email_admin_office(
#                 subject=f"Response to Ticket #{ticket.id}: {subject_display}",
#                 to_email=user_email,
#                 html=html,
#                 text_fallback=text,
#             )
#     except Exception:
#         logger.exception("Failed to send admin response email")

#     # Build sender info
#     sender_type = "Pharmacy" if ticket.pharmacy else "Driver"
#     sender_info = {
#         "type": sender_type,
#         "id": ticket.pharmacy.id if ticket.pharmacy else ticket.driver.id,
#         "name": ticket.pharmacy.name if ticket.pharmacy else ticket.driver.name,
#         "email": ticket.pharmacy.email if ticket.pharmacy else ticket.driver.email,
#     }

#     return JsonResponse(
#         {
#             "success": True,
#             "message": "Response added and ticket resolved.",
#             "ticket": {
#                 "ticket_id": ticket.id,
#                 "subject_key": ticket.subject,
#                 "subject": ticket.other_subject if ticket.subject == "other" else ticket.get_subject_display(),
#                 "message": ticket.message,
#                 "admin_response": ticket.admin_response,
#                 "status": ticket.status,
#                 "sender": sender_info,
#                 "created_at": ticket.created_at.strftime("%Y-%m-%d %H:%M:%S"),
#                 "updated_at": ticket.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
#             },
#         },
#         status=200
#     )


@csrf_protect
@admin_auth_required
@require_http_methods(["POST", "PATCH"])
def add_admin_response(request, ticket_id):
    """
    Admin-only API to add an admin response to a ticket.
    Automatically sets the status to 'resolved' if not already resolved.

    Expected JSON body:
    {
        "admin_response": "Your issue has been resolved..."
    }
    
    Timezone rule:
    - DB stores UTC
    - Email timestamps use settings.USER_TIMEZONE
    - Response timestamps use settings.USER_TIMEZONE
    """
    try:
        # 1️⃣ Fetch ticket
        try:
            ticket = ContactAdmin.objects.select_related("pharmacy", "driver").get(id=ticket_id)
        except ContactAdmin.DoesNotExist:
            return JsonResponse(
                {"success": False, "message": "Ticket not found."},
                status=404
            )

        # 2️⃣ Parse JSON
        try:
            data = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "message": "Invalid JSON payload."},
                status=400
            )

        admin_response = data.get("admin_response")
        if not admin_response or not admin_response.strip():
            return JsonResponse(
                {"success": False, "message": "Missing or empty 'admin_response'."},
                status=400
            )

        # 3️⃣ Update fields
        ticket.admin_response = admin_response.strip()

        # Auto-resolve if not resolved
        if ticket.status != "resolved":
            ticket.status = "resolved"

        ticket.save()

        # 4️⃣ Send email notification to ticket raiser
        try:
            # Get ticket raiser info
            user_email = None
            user_name = None
            user_type = None
            
            if ticket.pharmacy:
                user_email = ticket.pharmacy.email
                user_name = ticket.pharmacy.name
                user_type = "Pharmacy"
            elif ticket.driver:
                user_email = ticket.driver.email
                user_name = ticket.driver.name
                user_type = "Driver"
            
            if user_email:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                
                # ✅ Convert UTC to local timezone for email display
                now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)
                now_str = now_local.strftime("%b %d, %Y %H:%M %Z")
                
                logo_url = settings.LOGO_URL
                
                # Format subject for display
                subject_display = ticket.other_subject if ticket.subject == 'other' else ticket.get_subject_display()
                
                # Truncate original message for context (first 100 chars)
                message_context = ticket.message[:100] + "..." if len(ticket.message) > 100 else ticket.message

                html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Admin Response • {settings.COMPANY_OPERATING_NAME}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      @media (prefers-color-scheme: dark) {{
        body {{ background: #0b1220 !important; color: #e5e7eb !important; }}
        .card {{ background: #0f172a !important; border-color: #1f2937 !important; }}
        .muted {{ color: #94a3b8 !important; }}
      }}
    </style>
  </head>
  <body style="margin:0;padding:0;background:#f4f7f9;">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Admin response received for your support ticket.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="background:{brand_primary};padding:18px 20px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td align="left">
                      <img src="{logo_url}"
                           alt="{settings.COMPANY_OPERATING_NAME}"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Admin Response Received
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Hi {user_name}, we've responded to your ticket ✓
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Our admin team has reviewed and responded to your support ticket <strong>#{ticket.id}</strong>.
                </p>

                <div style="margin:18px 0;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                    ✓ Ticket Status: <span style="font-weight:700;">RESOLVED</span>
                  </p>
                </div>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Ticket ID</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">#{ticket.id}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Subject</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{subject_display}</td>
                    </tr>
                    <tr style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Responded On</td>
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
                    </tr>
                  </table>
                </div>

                <div style="margin:20px 0;background:#fffbeb;border-left:3px solid {brand_accent};border-radius:8px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
                    YOUR ORIGINAL MESSAGE:
                  </p>
                  <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#451a03;">
                    {message_context}
                  </p>
                </div>

                <div style="margin:20px 0;background:#f0fdfa;border-left:3px solid {brand_primary};border-radius:8px;padding:16px 18px;">
                  <p style="margin:0 0 8px;font:600 13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                    ADMIN RESPONSE:
                  </p>
                  <p style="margin:0;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;white-space:pre-wrap;">
{admin_response}
                  </p>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  If you have further questions or need additional assistance, please login to the portal and raise another Support Ticket by mentioning current Ticket ID. <strong>#{ticket.id}</strong>.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                        Thank you for contacting {settings.COMPANY_OPERATING_NAME} support. We're here to help!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {now_local.year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Admin Response Received - {settings.COMPANY_OPERATING_NAME}\n\n"
                    f"Hi {user_name},\n\n"
                    f"Our admin team has responded to your support ticket #{ticket.id}.\n\n"
                    f"Ticket ID: #{ticket.id}\n"
                    f"Subject: {subject_display}\n"
                    f"Status: RESOLVED\n"
                    f"Responded On: {now_str}\n\n"
                    "YOUR ORIGINAL MESSAGE:\n"
                    f"{message_context}\n\n"
                    "ADMIN RESPONSE:\n"
                    f"{admin_response}\n\n"
                    f"If you have further questions, reply to this email with your ticket ID #{ticket.id}.\n"
                )

                _send_html_email_admin_office(
                    subject=f"Response to Ticket #{ticket.id}: {subject_display}",
                    to_email=user_email,
                    html=html,
                    text_fallback=text,
                )
        except Exception:
            logger.exception("Failed to send admin response email")

        # Build sender info with proper timezone conversion
        def fmt_dt(dt):
            if not dt:
                return None
            # ✅ Convert to local time for response
            local_dt = timezone.localtime(dt, settings.USER_TIMEZONE)
            return local_dt.strftime("%Y-%m-%d %H:%M:%S")

        sender_type = "pharmacy" if ticket.pharmacy else "driver" if ticket.driver else "unknown"
        sender_info = None
        
        if ticket.pharmacy:
            sender_info = {
                "type": "Pharmacy",
                "id": ticket.pharmacy.id,
                "name": ticket.pharmacy.name,
                "email": ticket.pharmacy.email,
            }
        elif ticket.driver:
            sender_info = {
                "type": "Driver",
                "id": ticket.driver.id,
                "name": ticket.driver.name,
                "email": ticket.driver.email,
            }

        return JsonResponse(
            {
                "success": True,
                "message": "Response added and ticket resolved.",
                "ticket": {
                    "ticket_id": ticket.id,
                    "subject_key": ticket.subject,
                    "subject": ticket.other_subject if ticket.subject == "other" else ticket.get_subject_display(),
                    "message": ticket.message,
                    "admin_response": ticket.admin_response,
                    "status": ticket.status,
                    "sender_type": sender_type,
                    "sender": sender_info,
                    "created_at": fmt_dt(ticket.created_at),
                    "updated_at": fmt_dt(ticket.updated_at),
                },
            },
            status=200
        )

    except Exception as e:
        logger.exception("Error adding admin response")
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500
        )


# @csrf_exempt
# def get_ticket_status_metrics(request):
#     """
#     Returns counts of tickets by status:
#     - pending
#     - in_progress
#     - resolved
#     """
#     if request.method != "GET":
#         return JsonResponse(
#             {"success": False, "message": "Only GET method is allowed."},
#             status=405,
#         )

#     try:
#         pending_count = ContactAdmin.objects.filter(status="pending").count()
#         in_progress_count = ContactAdmin.objects.filter(status="in_progress").count()
#         resolved_count = ContactAdmin.objects.filter(status="resolved").count()
#         total_count = pending_count + in_progress_count + resolved_count

#         return JsonResponse(
#             {
#                 "success": True,
#                 "metrics": {
#                     "pending_tickets": pending_count,
#                     "in_progress_tickets": in_progress_count,
#                     "resolved_tickets": resolved_count,
#                     "total_tickets": total_count,
#                 },
#             },
#             status=200,
#         )

#     except Exception as e:
#         return JsonResponse(
#             {"success": False, "message": "Something went wrong.", "error": str(e)},
#             status=500,
#         )


@csrf_protect
@admin_auth_required
@require_http_methods(["GET"])
def get_ticket_status_metrics(request):
    """
    Admin-only API to get ticket metrics by status.
    
    Returns counts of tickets by status:
    - pending
    - in_progress
    - resolved
    - total
    """
    try:
        # ✅ Optimized: Single query using aggregation instead of 3 separate queries
        from django.db.models import Count, Q
        
        status_counts = ContactAdmin.objects.aggregate(
            pending_tickets=Count('id', filter=Q(status='pending')),
            in_progress_tickets=Count('id', filter=Q(status='in_progress')),
            resolved_tickets=Count('id', filter=Q(status='resolved')),
            total_tickets=Count('id')
        )

        return JsonResponse(
            {
                "success": True,
                "metrics": {
                    "pending_tickets": status_counts['pending_tickets'],
                    "in_progress_tickets": status_counts['in_progress_tickets'],
                    "resolved_tickets": status_counts['resolved_tickets'],
                    "total_tickets": status_counts['total_tickets'],
                },
            },
            status=200,
        )

    except Exception as e:
        logger.exception("Error fetching ticket status metrics")
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500,
        )



@csrf_exempt
@require_http_methods(["POST"])
def pharmacy_info_api(request):
    """
    API endpoint to store pharmacy information for internal analytics and baseline tracking.
    """
    # Parse JSON data from request body
    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON payload."},
            status=400
        )
    
    # Validate required fields
    required_fields = [
        'pharmacy_name', 'pharmacy_phone', 'pharmacy_email',
        'address_line_1', 'city', 'postal_code', 'store_hours',
        'contact_name', 'contact_role', 'contact_phone', 'contact_email',
        'estimated_deliveries_per_day', 'preferred_delivery_type',
        'delivery_radius_km'
    ]
    
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return JsonResponse(
            {"success": False, "error": f"Missing required fields: {', '.join(missing_fields)}"},
            status=400
        )
    
    # Validate consent
    if not data.get('consent_given'):
        return JsonResponse(
            {"success": False, "error": "Consent must be given to proceed"},
            status=400
        )
    
    # Create the pharmacy info record
    try:
        pharmacy_info = PharmacyInfo.objects.create(
            pharmacy_name=data['pharmacy_name'],
            pharmacy_phone=data['pharmacy_phone'],
            pharmacy_email=data['pharmacy_email'],

            address_line_1=data['address_line_1'],
            city=data['city'],
            postal_code=data['postal_code'],

            store_hours=data['store_hours'],

            contact_name=data['contact_name'],
            contact_role=data['contact_role'],
            contact_phone=data['contact_phone'],
            contact_email=data['contact_email'],

            currently_offers_delivery=bool(data.get('currently_offers_delivery', False)),

            estimated_deliveries_per_day=int(data['estimated_deliveries_per_day']),
            preferred_delivery_type=data['preferred_delivery_type'].strip().lower(),

            delivery_radius_km=int(data['delivery_radius_km']),

            signature_required=bool(data.get('signature_required', True)),
            id_verification_required=bool(data.get('id_verification_required', False)),
            special_delivery_instructions=data.get('special_delivery_instructions'),

            consent_given=bool(data.get('consent_given')),

            internal_notes=data.get('internal_notes'),
        )
    except Exception as e:
        logger.exception("Failed to create pharmacy info record")
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500
        )

    return JsonResponse(
        {
            "success": True,
            "message": f"Pharmacy information for '{pharmacy_info.pharmacy_name}' submitted successfully!",
            "pharmacy": {
                "id": pharmacy_info.id,
                "pharmacy_name": pharmacy_info.pharmacy_name,
                "contact_name": pharmacy_info.contact_name,
                "city": pharmacy_info.city,
                "estimated_deliveries_per_day": pharmacy_info.estimated_deliveries_per_day,
                "preferred_delivery_type": pharmacy_info.preferred_delivery_type,
                "created_at": pharmacy_info.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=201
    )






@csrf_protect
@require_http_methods(["GET"])
@pharmacy_auth_required
def get_pharmacy_cc_points(request: HttpRequest, pharmacy_id: int):
    """
    GET API: Returns CC Points and delivered orders count for a pharmacy.

    URL:
        /api/getPharmacyCCPoints/<pharmacy_id>/

    Response:
    {
        "success": true,
        "pharmacy_id": 1,
        "delivered_orders": 25,
        "cc_points": 400
    }
    """
    try:
        # ---------- Auth safety ----------
        # Ensure pharmacy can only access its own CC points
        if int(request.pharmacy.id) != int(pharmacy_id):
            return JsonResponse(
                {"success": False, "error": "Unauthorized access."},
                status=403
            )

        # ---------- Delivered orders count ----------
        delivered_orders_count = DeliveryOrder.objects.filter(
            pharmacy_id=pharmacy_id,
            status="delivered"
        ).count()

        # ---------- CC Points ----------
        points_obj = CCPointsAccount.objects.filter(
            pharmacy_id=pharmacy_id
        ).only("points_balance").first()

        cc_points = points_obj.points_balance if points_obj else 0

        return JsonResponse({
            "success": True,
            "pharmacy_id": pharmacy_id,
            "delivered_orders": delivered_orders_count,
            "cc_points": cc_points
        }, status=200)

    except Exception as e:
        # ⚠️ Log in production instead of exposing error
        print(f"Error in get_pharmacy_cc_points: {str(e)}")

        return JsonResponse(
            {
                "success": False,
                "error": "Failed to retrieve CC points."
            },
            status=500
        )

        

@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def upload_driver_identity_image(request):
    """
    Upload or replace a driver's identity/profile image to GCP
    (UBLA-safe) and store the public URL in Driver.identity_url
    """

    try:
        # ✅ Authenticated driver (trusted)
        driver = request.driver

        image_file = request.FILES.get("image")
        if not image_file:
            return JsonResponse({
                "success": False,
                "error": "image file is required"
            }, status=400)

        # ----------------------------
        # Build safe filename
        # ----------------------------
        ext = os.path.splitext(image_file.name)[1] or ".jpg"
        safe_name = "".join(c for c in driver.name if c.isalnum() or c in ("_", "-"))
        safe_email = driver.email.replace("@", "_").replace(".", "_")

        filename = f"{driver.id}_{safe_name}_{safe_email}{ext}"

        gcp_object_path = (
            f"{settings.GCP_DRIVER_INVOICE_FOLDER}/"
            f"{settings.GCP_DRIVER_PROFILE_FOLDER}/"
            f"{filename}"
        )

        # ----------------------------
        # Initialize GCP client
        # ----------------------------
        credentials = service_account.Credentials.from_service_account_file(
            settings.GCP_KEY_PATH
        )

        client = storage.Client(credentials=credentials)
        bucket = client.bucket(settings.GCP_BUCKET_NAME)
        blob = bucket.blob(gcp_object_path)

        image_file.seek(0)

        # ----------------------------
        # Upload (overwrite if exists)
        # ----------------------------
        blob.upload_from_file(
            image_file,
            content_type=mimetypes.guess_type(filename)[0] or "image/jpeg"
        )

        # ----------------------------
        # UBLA-safe public URL
        # ----------------------------
        public_url = f"https://storage.googleapis.com/{bucket.name}/{gcp_object_path}"

        # ----------------------------
        # Save URL in DB
        # ----------------------------
        driver.identity_url = public_url
        driver.save(update_fields=["identity_url"])

        return JsonResponse({
            "success": True,
            "driver_id": driver.id,
            "identity_url": public_url,
            "message": "Driver identity image uploaded successfully"
        }, status=200)

    except Exception as e:
        logger.exception("Error uploading driver identity image")
        return JsonResponse({
            "success": False,
            "error": "Failed to upload identity image"
        }, status=500)



def generate_acknowledgement_pdf(order, signature_image_path):
    """
    Generate professional acknowledgement receipt PDF with customer signature
    """
    buffer = BytesIO()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=60
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # ==================== CUSTOM STYLES ====================
    
    # Modern color palette
    PRIMARY_COLOR = colors.HexColor('#0F172A')      # Deep slate
    ACCENT_COLOR = colors.HexColor('#10B981')       # Success green
    LIGHT_BG = colors.HexColor('#F8FAFC')           # Light background
    BORDER_GRAY = colors.HexColor('#E2E8F0')        # Border gray
    TEXT_DARK = colors.HexColor('#1E293B')          # Dark text
    TEXT_GRAY = colors.HexColor('#64748B')          # Gray text
    
    # Title style
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=PRIMARY_COLOR,
        fontName='Helvetica-Bold',
        alignment=TA_CENTER,
        spaceAfter=10,
        leading=32
    )
    
    # Subtitle style
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=ACCENT_COLOR,
        fontName='Helvetica-Bold',
        alignment=TA_CENTER,
        spaceAfter=30
    )
    
    # Section header
    section_header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=PRIMARY_COLOR,
        fontName='Helvetica-Bold',
        spaceAfter=10,
        spaceBefore=20,
        leading=16
    )
    
    # Body text
    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontSize=10,
        textColor=TEXT_DARK,
        fontName='Helvetica',
        leading=14,
        spaceAfter=8
    )
    
    # Small text
    small_text_style = ParagraphStyle(
        'SmallText',
        parent=styles['Normal'],
        fontSize=9,
        textColor=TEXT_GRAY,
        fontName='Helvetica',
        leading=12
    )
    
    # Footer style
    footer_style = ParagraphStyle(
        'FooterStyle',
        parent=styles['Normal'],
        fontSize=8,
        textColor=TEXT_GRAY,
        fontName='Helvetica-Oblique',
        alignment=TA_CENTER,
        leading=11
    )
    
    # ==================== HEADER WITH LOGO ====================
    
    try:
        logo_path = settings.LOGO_PATH
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=2*inch, height=1.4*inch)
            logo.hAlign = 'CENTER'
            story.append(logo)
            story.append(Spacer(1, 15))
        else:
            raise FileNotFoundError
    except Exception as e:
        logger.warning(f"Logo not found, using text fallback: {e}")
        logo_text = Paragraph(
            '<b><font size="18" color="#10B981">Cana</font><font size="18" color="#0F172A">LogistiX</font></b>',
            ParagraphStyle('LogoText', parent=styles['Normal'], alignment=TA_CENTER)
        )
        story.append(logo_text)
        story.append(Spacer(1, 10))
    
    company_name = settings.COMPANY_OPERATING_NAME
    company_subgroup_name = settings.COMPANY_SUB_GROUP_NAME
    corporation_name = settings.CORPORATION_NAME
    corporation_business_number = settings.COMPANY_BUSINESS_NUMBER

    email_help_desk = settings.EMAIL_HELP_DESK
    
    # Company info
    company_info = f'''
    <para alignment="center">
    <font size="9" color="#64748B">{company_name} Delivery Services<br/>
    {company_subgroup_name} | Operating Name of {corporation_name}<br/>
    BN: {corporation_business_number} | {email_help_desk}</font>
    </para>
    '''
    story.append(Paragraph(company_info, small_text_style))
    story.append(Spacer(1, 25))
    
    # ==================== TITLE SECTION ====================
    
    story.append(Paragraph("DELIVERY ACKNOWLEDGEMENT", title_style))
    story.append(Paragraph("Medicine Received in Proper Condition", subtitle_style))
    
    # Horizontal divider
    line_table = Table([['']], colWidths=[6.5*inch])
    line_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 2, ACCENT_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(line_table)
    story.append(Spacer(1, 25))
    
    # ==================== ACKNOWLEDGEMENT STATEMENT ====================
    
    # current_date = timezone.now().strftime("%B %d, %Y at %I:%M %p")
    current_date = timezone.localtime(timezone.now(), settings.USER_TIMEZONE).strftime("%B %d, %Y at %I:%M %p")
    
    acknowledgement_text = f'''
    <para alignment="justify">
    <font size="10" color="#1E293B">
    I, <b>{order.customer_name}</b>, hereby acknowledge that I have received the pharmaceutical 
    delivery from <b>{order.pharmacy.name}</b> on <b>{current_date}</b>. 
    I confirm that all medicines have been received in <b>proper condition</b>, with intact packaging, 
    correct labeling, and no visible damage or tampering. The delivery was completed by 
    <b>{settings.COMPANY_OPERATING_NAME} Delivery Services</b> in accordance with pharmaceutical handling protocols.
    </font>
    </para>
    '''
    story.append(Paragraph(acknowledgement_text, body_style))
    story.append(Spacer(1, 25))
    
    # ==================== ORDER DETAILS ====================
    
    story.append(Paragraph("Order Information", section_header_style))

    if order.delivered_at:
      delivered_local = timezone.localtime(order.delivered_at, settings.USER_TIMEZONE)
      delivered_str = delivered_local.strftime("%B %d, %Y at %I:%M %p")
    else:
      delivered_str = current_date
    
    order_details_data = [
        ['Order ID:', f"#{order.id}"],
        ['Order Date:', order.pickup_day.strftime("%B %d, %Y")],
        ['Delivery Date:', delivered_str],
        ['Delivery Status:', 'Delivered Successfully'],
    ]

    
    order_table = Table(order_details_data, colWidths=[2*inch, 4.5*inch])
    order_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('TEXTCOLOR', (0, 0), (0, -1), TEXT_GRAY),
        ('TEXTCOLOR', (1, 0), (1, -1), TEXT_DARK),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    story.append(order_table)
    story.append(Spacer(1, 20))
    
    # ==================== PARTY INFORMATION ====================
    
    story.append(Paragraph("Party Information", section_header_style))
    
    # Customer, Pharmacy, Driver info side by side
    customer_info = f'''
    <font size="8" color="#64748B"><b>CUSTOMER</b></font><br/>
    <font size="10" color="#0F172A"><b>{order.customer_name}</b></font><br/>
    <font size="9" color="#64748B">Phone: {order.customer_phone}<br/>
    Delivery Address:<br/>
    {order.drop_address}<br/>
    {order.drop_city}</font>
    '''
    
    pharmacy_info = f'''
    <font size="8" color="#64748B"><b>PHARMACY</b></font><br/>
    <font size="10" color="#0F172A"><b>{order.pharmacy.name}</b></font><br/>
    <font size="9" color="#64748B">
    {order.pharmacy.store_address}<br/>
    {order.pharmacy.city}, {order.pharmacy.province}<br/>
    Phone: {order.pharmacy.phone_number}<br/>
    Email: {order.pharmacy.email}</font>
    '''
    
    driver_name = order.driver.name if order.driver else "N/A"
    driver_phone = order.driver.phone_number if order.driver else "N/A"
    driver_vehicle = order.driver.vehicle_number if (order.driver and order.driver.vehicle_number) else "N/A"
    
    driver_info = f'''
    <font size="8" color="#64748B"><b>DELIVERY PARTNER</b></font><br/>
    <font size="10" color="#0F172A"><b>{driver_name}</b></font><br/>
    <font size="9" color="#64748B">
    Phone: {driver_phone}<br/>
    Vehicle: {driver_vehicle}<br/>
    Service: {settings.COMPANY_OPERATING_NAME}<br/>
    </font>
    '''
    
    party_info_data = [
        [Paragraph(customer_info, body_style), 
         Paragraph(pharmacy_info, body_style),
         Paragraph(driver_info, body_style)]
    ]
    
    party_table = Table(party_info_data, colWidths=[2.16*inch, 2.17*inch, 2.17*inch])
    party_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_GRAY),
        ('INNERGRID', (0, 0), (-1, -1), 1, BORDER_GRAY),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    story.append(party_table)
    story.append(Spacer(1, 25))
    
    # ==================== DELIVERY VERIFICATION ====================
    
    story.append(Paragraph("Delivery Verification", section_header_style))
    
    verification_items = [
        "✓ All medicines received in original sealed packaging",
        "✓ No visible damage, tampering, or temperature abuse",
        "✓ Labels are intact and readable with correct patient information",
        "✓ Delivery completed within required timeframe",
        "✓ All items listed on the prescription/order were delivered"
    ]
    
    for item in verification_items:
        item_para = Paragraph(f'<font size="9" color="#1E293B">{item}</font>', body_style)
        story.append(item_para)
    
    story.append(Spacer(1, 25))
    
    # ==================== CUSTOMER SIGNATURE ====================
    
    story.append(Paragraph("Customer Signature", section_header_style))
    
    # Add signature image
    try:
        signature_img = Image(signature_image_path, width=3*inch, height=1.2*inch)
        signature_img.hAlign = 'LEFT'
        
        signature_data = [
            [signature_img, ''],
            ['', ''],
            [f'Signed by: {order.customer_name}', f'Date: {current_date}'],
        ]
        
        signature_table = Table(signature_data, colWidths=[3.5*inch, 3*inch])
        signature_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), LIGHT_BG),
            ('BOX', (0, 0), (0, 0), 1, BORDER_GRAY),
            ('LINEABOVE', (0, 2), (0, 2), 1, TEXT_GRAY),
            ('FONTNAME', (0, 2), (-1, 2), 'Helvetica'),
            ('FONTSIZE', (0, 2), (-1, 2), 9),
            ('TEXTCOLOR', (0, 2), (-1, 2), TEXT_GRAY),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (0, 0), 10),
            ('BOTTOMPADDING', (0, 0), (0, 0), 10),
            ('TOPPADDING', (0, 2), (-1, 2), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(signature_table)
    except Exception as e:
        logger.error(f"Error adding signature image: {e}")
        story.append(Paragraph('<font color="#DC2626">Error: Signature image could not be added</font>', body_style))
    
    story.append(Spacer(1, 30))
    
    # ==================== IMPORTANT NOTICE ====================
    
    story.append(Paragraph("Important Notice", section_header_style))

    
    
    notice_text = f'''
    <para alignment="justify">
    <font size="9" color="#64748B">
    This acknowledgement serves as proof of delivery and confirmation that all medicines were 
    received in acceptable condition. Any issues with the delivered medicines should be reported 
    immediately to the pharmacy and {company_name}. By signing this document, the customer confirms 
    receipt and assumes responsibility for the proper storage and use of the delivered pharmaceutical products.
    </font>
    </para>
    '''
    story.append(Paragraph(notice_text, small_text_style))
    story.append(Spacer(1, 40))
    
    # ==================== FOOTER ====================
    
    footer_text = f'''
    <i>This acknowledgement was automatically generated by {settings.COMPANY_OPERATING_NAME} delivery system.<br/>
    Document ID: ACK-{order.id:06d} | Generated: {current_date}<br/>
    For questions or concerns, contact: {settings.EMAIL_HELP_DESK}<br/>
    © {timezone.localtime(timezone.now(), settings.USER_TIMEZONE).year} {settings.COMPANY_OPERATING_NAME} - {settings.COMPANY_SUB_GROUP_NAME}. All rights reserved.</i>
    '''
    
    story.append(Paragraph(footer_text, footer_style))
    
    # Build PDF
    doc.build(story)
    logger.info(f"Generated acknowledgement PDF for order {order.id}")
    
    return buffer


@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def upload_signature_acknowledgement(request):
    try:
        order_id = request.POST.get("orderId")
        signature_base64 = request.POST.get("signature")

        if not order_id or not signature_base64:
            return JsonResponse(
                {"success": False, "error": "orderId and signature are required"},
                status=400
            )

        order = get_object_or_404(
            DeliveryOrder.objects.select_related("pharmacy", "driver"),
            id=order_id
        )

        if order.status != "inTransit":
            return JsonResponse(
                {"success": False, "error": "Order must be in transit status"},
                status=400
            )

        if "base64," in signature_base64:
            signature_base64 = signature_base64.split("base64,", 1)[1]

        signature_base64 = "".join(signature_base64.split())
        padding = len(signature_base64) % 4
        if padding:
            signature_base64 += "=" * (4 - padding)

        signature_bytes = base64.b64decode(signature_base64, validate=True)

        if len(signature_bytes) < 100:
            return JsonResponse(
                {"success": False, "error": "Signature data too small"},
                status=400
            )

        temp_signature_path = f"/tmp/signature_{order.id}_{int(time.time())}.png"

        img = PILImage.open(BytesIO(signature_bytes))
        if img.mode in ("RGBA", "LA"):
            bg = PILImage.new("RGB", img.size, (255, 255, 255))
            bg.paste(img, mask=img.split()[-1])
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")

        img.save(temp_signature_path, "PNG")

        # ✅ THIS IS THE KEY PART
        timezone.activate(settings.USER_TIMEZONE)
        try:
            pdf_buffer = generate_acknowledgement_pdf(
                order=order,
                signature_image_path=temp_signature_path
            )
            pdf_buffer.seek(0)
        finally:
            timezone.deactivate()  # restore UTC

        credentials = service_account.Credentials.from_service_account_file(
            settings.GCP_KEY_PATH
        )
        client = storage.Client(credentials=credentials)
        bucket = client.bucket(settings.GCP_BUCKET_NAME)

        filename = f"order_{order.id}_pharmacy_{order.pharmacy.id}_{int(time.time())}.pdf"
        gcp_path = (
            f"{settings.GCP_INVOICE_FOLDER}/"
            f"{settings.GCP_CUSTOMER_PHARMACY_SIGNED_ACKNOWLEDGEMENTS}/"
            f"{filename}"
        )

        blob = bucket.blob(gcp_path)
        blob.upload_from_file(pdf_buffer, content_type="application/pdf")

        public_url = f"https://storage.googleapis.com/{bucket.name}/{gcp_path}"

        order.signature_ack_url = public_url
        order.save(update_fields=["signature_ack_url"])

        if os.path.exists(temp_signature_path):
            os.remove(temp_signature_path)

        return JsonResponse({
            "success": True,
            "order_id": order.id,
            "acknowledgement_url": public_url,
            "message": "Acknowledgement PDF generated and uploaded successfully"
        })

    except Exception:
        logger.exception("Unexpected error in upload_signature_acknowledgement")
        return JsonResponse(
            {"success": False, "error": "An unexpected error occurred"},
            status=500
        )


@csrf_protect
@require_http_methods(["POST"])
@driver_auth_required
def verify_customer_id(request):
    """
    API endpoint to mark ID verification as completed for an order

    Expected POST parameters:
    - orderId: The delivery order ID
    - verified: Boolean (ignored)

    Returns:
    - JSON response with success status
    """
    try:
        order_id = request.POST.get('orderId')
        _ = request.POST.get('verified')  # ignored

        if not order_id:
            return JsonResponse({
                'success': False,
                'error': 'orderId is required'
            }, status=400)

        driver = request.driver  # 🔐 AUTH SOURCE OF TRUTH

        order = get_object_or_404(DeliveryOrder, id=order_id)

        if order.driver_id != driver.id:
            return JsonResponse({
                'success': False,
                'error': 'Driver is not assigned to this order'
            }, status=403)

        if order.status not in ['inTransit', 'delivered']:
            return JsonResponse({
                'success': False,
                'error': 'ID verification can only be done during transit or delivery'
            }, status=400)

        # ✅ MAIN LOGIC (unchanged)
        if not order.id_verified:
            order.id_verified = True
            order.save(update_fields=['id_verified', 'updated_at'])

        logger.info(
            f"ID verification set TRUE for order {order.id} by driver {driver.id}"
        )

        return JsonResponse({
            'success': True,
            'order_id': order.id,
            'message': 'ID verification recorded successfully'
        })

    except Exception:
        logger.exception("Unexpected error in verify_customer_id")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred'
        }, status=500)



# @csrf_exempt
# @require_http_methods(["GET"])
# def get_driver_cc_points(request, driver_id):
#     try:
#         # (Optional but recommended) Validate driver exists
#         if not Driver.objects.filter(id=driver_id).exists():
#             return JsonResponse({
#                 "success": False,
#                 "error": "Driver not found"
#             }, status=404)

#         # 1) Delivered orders count (ONLY by status)
#         delivered_orders_count = DeliveryOrder.objects.filter(
#             driver_id=driver_id,
#             status="delivered"
#         ).count()

#         # 2) Points from CCPointsAccount table (no multiplication)
#         points_obj = CCPointsAccount.objects.filter(driver_id=driver_id).first()
#         cc_points = points_obj.points_balance if points_obj else 0

#         return JsonResponse({
#             "success": True,
#             "driver_id": driver_id,
#             "delivered_orders": delivered_orders_count,
#             "cc_points": cc_points
#         })

#     except Exception as e:
#         return JsonResponse({
#             "success": False,
#             "error": str(e)
#         }, status=500)

@csrf_protect
@require_http_methods(["GET"])
@driver_auth_required
def get_driver_cc_points(request, driver_id):
    """
    GET API to fetch CC points and delivered orders count for a driver.
    """

    try:
        # 🔐 AUTHORIZATION CHECK
        # driver_auth_required already authenticated the driver
        if int(request.driver.id) != int(driver_id):
            return JsonResponse({
                "success": False,
                "error": "Unauthorized access"
            }, status=403)

        # 1) Delivered orders count (ONLY by status)
        delivered_orders_count = DeliveryOrder.objects.filter(
            driver_id=driver_id,
            status="delivered"
        ).count()

        # 2) Points from CCPointsAccount table (no multiplication)
        points_obj = CCPointsAccount.objects.filter(driver_id=driver_id).first()
        cc_points = points_obj.points_balance if points_obj else 0

        return JsonResponse({
            "success": True,
            "driver_id": driver_id,
            "delivered_orders": delivered_orders_count,
            "cc_points": cc_points
        }, status=200)

    except Exception as e:
        logger.exception("Error fetching driver CC points")
        return JsonResponse({
            "success": False,
            "error": "An unexpected error occurred"
        }, status=500)


@csrf_protect
@require_http_methods(["GET"])
@pharmacy_auth_required
def get_active_payment_methods(request):
    """
    Return all active payment methods with details.
    - DB timestamps remain UTC
    - Response timestamps are converted to settings.USER_TIMEZONE
    - Read-only, pharmacy-authenticated endpoint
    """

    try:
        active_payments = PaymentInformation.objects.filter(
            is_active=True
        ).order_by("payment_type")

        results = []

        for payment in active_payments:
            created_local = timezone.localtime(
                payment.created_at, settings.USER_TIMEZONE
            ) if payment.created_at else None

            updated_local = timezone.localtime(
                payment.updated_at, settings.USER_TIMEZONE
            ) if payment.updated_at else None

            results.append({
                "id": payment.id,
                "payment_type": payment.payment_type,
                "label": payment.label,
                "details": payment.data,   # JSON payload (EFT, cheque, etc.)
                "is_active": payment.is_active,

                # Local-time response
                "created_at": created_local.isoformat() if created_local else None,
                "updated_at": updated_local.isoformat() if updated_local else None,

                "updated_by": payment.updated_by,
            })

        return JsonResponse(
            {
                "success": True,
                "count": len(results),
                "payment_methods": results,
            },
            status=200
        )

    except Exception:
        logger.exception("Failed to fetch active payment methods")
        return JsonResponse(
            {
                "success": False,
                "error": "Failed to retrieve payment methods"
            },
            status=500
        )