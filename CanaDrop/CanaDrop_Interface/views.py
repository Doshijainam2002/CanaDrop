# Standard Library
import hashlib
import io
import json
import logging
import os
import random
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from io import BytesIO
from itertools import chain
from random import sample
import mimetypes
import base64
import time

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
from django.db.models import Count, Sum, Q
from django.http import (
    HttpRequest, HttpResponse, HttpResponseBadRequest,
    HttpResponseNotAllowed, JsonResponse
)
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.utils.timezone import now
from django.template.loader import render_to_string

# Local App Models
from .models import *



# Add this for better error logging
logger = logging.getLogger(__name__)

#Helper Functions for Email
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


#Page Logins
def pharmacyLoginView(request):
    return render(request, 'pharmacyLogin.html')

def pharmacyRegisterView(request):
    return render(
        request,
        "pharmacyRegister.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )


def pharmacyDashboardView(request):
    return render(
        request,
        "pharmacyDashboard.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

def pharmacyForgotPasswordView(request):
    return render(request, 'pharmacyForgotPassword.html')

def pharmacyOrdersView(request):
    return render(request, 'pharmacyOrders.html')

def pharmacyInvoicesView(request):
    return render(request, 'pharmacyInvoices.html')

def driverLoginView(request):
    return render(request, 'driverLogin.html')

def driverDashboardView(request):
    return render(request, 'driverDashboard.html')

def driverAcceptedDeliveriesView(request):
    return render(request, 'driverAcceptedDeliveries.html')

def driverFinancesView(request):
    return render(request, 'driverFinances.html')

def driverForgotPasswordView(request):
    return render(request, 'driverForgotPassword.html')

def driverRegisterView(request):
    return render(
        request,
        "driverRegister.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

def contactAdminView(request):
    return render(request, 'contactAdmin.html')

def landingView(request):
    return render(request, 'landingPage.html')


def pharmacyProfileView(request):
    return render(
        request,
        "pharmacyProfile.html",
        {
            "GOOGLE_MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY
        }
    )

def adminLoginView(request):
    return render(request, 'adminLogin.html')

def adminDashboardView(request):
    return render(request, 'adminDashboard.html')

def adminOrdersView(request):
    return render(request, 'adminOrders.html')

def adminPharmaciesView(request):
    return render(request, 'adminPharmacies.html')

def adminOrdersView(request):
    return render(request, 'adminOrders.html')

def adminInvoicesView(request):
    return render(request, 'adminInvoices.html')

def adminSupportView(request):
    return render(request, 'adminSupport.html')

def adminDriversView(request):
    return render(request, 'adminDrivers.html')

def pharmacyTrialOnboarding(request):
    return render(request, 'pharmacyTrial.html')

def pharmacyCCPointsView(request):
    return render(request, 'pharmacyCCPoints.html')

def driverIdentityView(request):
    return render(request, 'driverIdentity.html')

def driverCCPointsView(request):
    return render(request, 'driverCCPoints.html')



@csrf_exempt
def pharmacy_login_api(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Only POST method allowed"}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")
    except Exception:
        return JsonResponse({"success": False, "message": "Invalid JSON"}, status=400)

    if not email or not password:
        return JsonResponse({"success": False, "message": "Email and password required"}, status=400)

    try:
        pharmacy = Pharmacy.objects.get(email=email)
    except Pharmacy.DoesNotExist:
        return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)

    if check_password(password, pharmacy.password):
        return JsonResponse({
            "success": True,
            "id": pharmacy.id
        })
    else:
        return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)

# @csrf_exempt
# def pharmacy_login_api(request):
#     if request.method != "POST":
#         return JsonResponse({"success": False, "message": "Only POST method allowed"}, status=405)

#     try:
#         data = json.loads(request.body)
#         email = data.get("email")
#         password = data.get("password")
#     except Exception:
#         return JsonResponse({"success": False, "message": "Invalid JSON"}, status=400)

#     if not email or not password:
#         return JsonResponse({"success": False, "message": "Email and password required"}, status=400)

#     try:
#         pharmacy = Pharmacy.objects.get(email=email)
#     except Pharmacy.DoesNotExist:
#         return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)

#     if check_password(password, pharmacy.password):
#         issued_at = timezone.now()  # UTC
#         expires_at = issued_at + timedelta(hours=settings.JWT_EXPIRY_HOURS)

#         payload = {
#             "pharmacy_id": pharmacy.id,
#             "email": pharmacy.email,
#             "iat": int(issued_at.timestamp()),
#             "exp": int(expires_at.timestamp()),
#         }

#         token = jwt.encode(
#             payload,
#             settings.JWT_SECRET_KEY,
#             algorithm=settings.JWT_ALGORITHM
#         )

#         return JsonResponse({
#             "success": True,
#             "id": pharmacy.id,
#             "token": token,
#             "expiresAt": timezone.localtime(expires_at, settings.USER_TIMEZONE).isoformat(),
#         })

#     return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)



def validate_address_city(address, city):
    """
    Validate that the address belongs to the provided city using Google Geocoding API.
    Returns True if valid, False otherwise.
    """
    try:
        url = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            "address": f"{address}, {city}",
            "key": settings.GOOGLE_MAPS_API_KEY
        }
        response = requests.get(url, params=params).json()
        if response['status'] != 'OK':
            return False
        # Check if the city exists in the formatted address
        formatted_address = response['results'][0]['formatted_address']
        return city.lower() in formatted_address.lower()
    except Exception as e:
        # print("Address validation failed:", e)
        return False


def get_distance_km(pickup_address, pickup_city, drop_address, drop_city):
    """
    Calculate the distance in kilometers between pickup and drop locations
    using Google Maps Distance Matrix API.
    """
    # Validate pickup and drop addresses
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
            "units": "metric"
        }
        response = requests.get(url, params=params).json()
        distance_meters = response['rows'][0]['elements'][0]['distance']['value']
        distance_km = distance_meters / 1000  # convert meters to km
        return distance_km, None
    except Exception as e:
        # print("Distance calculation failed:", e)
        return 0, "Failed to calculate distance"



def create_order_tracking_entry(order_id, step='pending', performed_by=None, note=None, image_url=None):
    """
    Function to create tracking entries for orders
    """
    try:
        # print(f"Creating tracking entry for order ID: {order_id}")
        
        # Get the order object
        order = DeliveryOrder.objects.get(id=order_id)
        # print(f"Order found: {order}")
        
        # Create tracking entry with OrderTracking model
        tracking_entry = OrderTracking.objects.create(
            order=order,
            driver=None,  # Always null for this API
            pharmacy=order.pharmacy,  # Add pharmacy from order
            step=step,
            performed_by=performed_by or f'Pharmacy: {order.pharmacy.name}',
            note=note or f'Order {step}',
            image_url=image_url
        )
        
        # Force commit
        transaction.commit()
        # print(f"Tracking entry created and committed: ID={tracking_entry.id}")
        
        # Verify it was saved
        tracking_count = OrderTracking.objects.filter(order=order).count()
        # print(f"Total tracking entries for order {order.id}: {tracking_count}")
        
        return {
            "success": True,
            "tracking_id": tracking_entry.id,
            "step": tracking_entry.step,
            "performed_by": tracking_entry.performed_by,
            "timestamp": tracking_entry.timestamp.isoformat(),
            "message": "Tracking entry created successfully"
        }
        
    except DeliveryOrder.DoesNotExist:
        # print(f"Order with ID {order_id} not found")
        return {
            "success": False,
            "error": f"Order with ID {order_id} not found"
        }
    except Exception as e:
        # print(f"Error creating tracking entry: {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "error": str(e)
        }




@csrf_exempt
def create_delivery_order(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            # -----------------------------
            # Required fields
            # -----------------------------
            pharmacy_id = data.get('pharmacyId')
            pickup_address = data.get('pickupAddress')
            pickup_city = data.get('pickupCity')
            pickup_day = data.get('pickupDay')
            drop_address = data.get('dropAddress')
            drop_city = data.get('dropCity')

            # Optional existing fields
            customer_name = data.get('customerName')
            customer_phone = data.get('customerPhone')

            # Optional NEW fields
            signature_required = data.get('signatureRequired')
            id_verification_required = data.get('idVerificationRequired')
            alternate_contact = data.get('alternateContact')
            delivery_notes = data.get('deliveryNotes')

            # -----------------------------
            # Validation
            # -----------------------------
            if not all([pharmacy_id, pickup_address, pickup_city, pickup_day, drop_address, drop_city]):
                return JsonResponse(
                    {"success": False, "error": "Missing required fields"},
                    status=400
                )

            pharmacy = Pharmacy.objects.get(id=pharmacy_id)

            # -----------------------------
            # Distance calculation
            # -----------------------------
            distance_km, error = get_distance_km(
                pickup_address, pickup_city, drop_address, drop_city
            )
            if error:
                return JsonResponse({"success": False, "error": error}, status=400)

            # -----------------------------
            # Rate calculation
            # -----------------------------
            rate_entry = DeliveryDistanceRate.objects.filter(
                min_distance_km__lte=distance_km
            ).order_by('min_distance_km').last()

            rate = rate_entry.rate if rate_entry else 0

            # -----------------------------
            # Create kwargs (lean + safe)
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

            # -----------------------------
            # Optional compliance fields
            # -----------------------------
            if signature_required is not None:
                create_kwargs["signature_required"] = bool(signature_required)

            if id_verification_required is not None:
                create_kwargs["id_verification_required"] = bool(id_verification_required)

            if alternate_contact:
                create_kwargs["alternate_contact"] = alternate_contact

            if delivery_notes:
                create_kwargs["delivery_notes"] = delivery_notes

            # -----------------------------
            # Create order
            # -----------------------------
            with transaction.atomic():
                order = DeliveryOrder.objects.create(**create_kwargs)

                tracking_result = create_order_tracking_entry(
                    order_id=order.id,
                    step='pending',
                    performed_by=f'Pharmacy: {pharmacy.name}',
                    note='Order created and pending driver acceptance'
                )

            # -----------------------------
            # Response
            # -----------------------------
            response_data = {
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
                "message": "Order and tracking created successfully"
            }

            return JsonResponse(response_data, status=201)

        except Pharmacy.DoesNotExist:
            return JsonResponse(
                {"success": False, "error": "Pharmacy not found"},
                status=404
            )

        except Exception as e:
            import traceback
            traceback.print_exc()
            return JsonResponse(
                {"success": False, "error": str(e)},
                status=500
            )

    return JsonResponse(
        {"success": False, "error": "Invalid HTTP method"},
        status=405
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
    
    print(f"🚗 Calculating distance from '{full_pickup}' to '{full_drop}'")
    
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
        
        print(f"📊 Distance Matrix API Status: {data.get('status')}")
        
        # Check overall API response
        if data.get('status') != 'OK':
            error_msg = f"Distance Matrix API error: {data.get('status', 'UNKNOWN')}"
            if 'error_message' in data:
                error_msg += f" - {data['error_message']}"
            print(f"❌ {error_msg}")
            return None, error_msg
        
        # Check if we have valid response structure
        rows = data.get('rows', [])
        if not rows or not rows[0].get('elements'):
            return None, "No route data returned from Google Maps"
            
        element = rows[0]['elements'][0]
        element_status = element.get('status')
        
        print(f"📍 Route Status: {element_status}")
        
        if element_status == 'OK':
            distance_meters = element.get('distance', {}).get('value')
            if distance_meters is None:
                return None, "Distance data not found in response"
                
            distance_km = distance_meters / 1000
            duration_text = element.get('duration', {}).get('text', 'Unknown')
            
            print(f"✅ Distance: {distance_km} km, Duration: {duration_text}")
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
        print(f"❌ {error_msg}")
        return None, error_msg
    except Exception as e:
        error_msg = f"Distance calculation failed: {str(e)}"
        print(f"❌ {error_msg}")
        import traceback
        traceback.print_exc()
        return None, error_msg


@csrf_exempt
def get_delivery_rate(request):
    if request.method == "GET":
        try:
            pickup_address = request.GET.get('pickupAddress')
            pickup_city = request.GET.get('pickupCity')
            drop_address = request.GET.get('dropAddress')
            drop_city = request.GET.get('dropCity')

            # Validate required fields
            if not all([pickup_address, pickup_city, drop_address, drop_city]):
                return JsonResponse({"success": False, "error": "Missing required fields"}, status=400)

            # Get distance directly - no separate address validation
            distance_km, error = get_distance_km(pickup_address, pickup_city, drop_address, drop_city)
            if error:
                return JsonResponse({"success": False, "error": error}, status=400)

            # Determine rate from DeliveryDistanceRate model
            rate_entry = DeliveryDistanceRate.objects.filter(
                min_distance_km__lte=distance_km
            ).order_by('min_distance_km').last()
            rate = rate_entry.rate if rate_entry else 0

            return JsonResponse({
                "success": True,
                "distance_km": distance_km,
                "rate": float(rate)  # Ensure it's a number, not Decimal
            })

        except Exception as e:
            print(f"❌ Exception in get_delivery_rate: {str(e)}")
            import traceback
            traceback.print_exc()
            return JsonResponse({"success": False, "error": f"Server error: {str(e)}"}, status=500)

    return JsonResponse({"success": False, "error": "Invalid HTTP method"}, status=405)




@csrf_exempt
def get_pharmacy_orders(request, pharmacy_id):
    if request.method == "GET":
        try:
            # Check if pharmacy exists
            pharmacy = Pharmacy.objects.get(id=pharmacy_id)
            
            # Fetch only latest 10 orders for this pharmacy
            orders = DeliveryOrder.objects.filter(pharmacy=pharmacy).order_by('-id')[:10].values(
                "id",
                "customer_name",
                "pickup_address",
                "pickup_city",
                "drop_address",
                "drop_city",
                "pickup_day",
                "rate",
                "status"
            )

            return JsonResponse(list(orders), safe=False, status=200)

        except Pharmacy.DoesNotExist:
            return JsonResponse({"error": "Pharmacy not found"}, status=404)

    return JsonResponse({"error": "Invalid request method"}, status=405)



class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)




@csrf_exempt
@require_http_methods(["GET"])
def pharmacy_orders_api(request, pharmacy_id):
    try:
        # Validate pharmacy exists
        pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

        # Get all orders for this pharmacy with related data
        orders = (
            DeliveryOrder.objects
            .filter(pharmacy=pharmacy)
            .select_related('driver')  # ✅ efficiency, no behavior change
            .prefetch_related('tracking_entries', 'images')
            .order_by('-created_at')
        )

        orders_data = []

        for order in orders:
            # -----------------------------
            # Tracking timeline
            # -----------------------------
            tracking_entries = list(
                order.tracking_entries.all().values(
                    'step', 'performed_by', 'timestamp', 'note', 'image_url'
                )
            )

            for entry in tracking_entries:
                entry['timestamp'] = (
                    entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    if entry['timestamp'] else None
                )

            # -----------------------------
            # Images grouped by stage
            # -----------------------------
            images_by_stage = {
                'handover': [],
                'pickup': [],
                'delivered': []
            }

            for image in order.images.all():
                images_by_stage[image.stage].append({
                    'image_url': image.image_url,
                    'uploaded_at': image.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
                })

            total_images = sum(len(v) for v in images_by_stage.values())

            # -----------------------------
            # Progress calculation
            # -----------------------------
            progress_map = {
                'pending': 25,
                'accepted': 50,
                'picked_up': 75,
                'delivered': 100,
                'cancelled': 0
            }

            # -----------------------------
            # Core order payload (UNCHANGED)
            # -----------------------------
            order_data = {
                'id': order.id,
                'pickup_address': order.pickup_address,
                'pickup_city': order.pickup_city,
                'pickup_day': order.pickup_day.strftime('%Y-%m-%d'),
                'drop_address': order.drop_address,
                'drop_city': order.drop_city,
                'status': order.status,
                'rate': order.rate,
                'customer_name': order.customer_name,
                'customer_phone': order.customer_phone,
                'alternate_contact': order.alternate_contact,
                'signature_required': order.signature_required,
                'signature_ack_url' : order.signature_ack_url,
                'id_verification_required': order.id_verification_required,
                "id_verified" : order.id_verified,
                'delivery_notes': order.delivery_notes,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': order.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'driver_id': order.driver.id if order.driver else None,
                'driver_name': order.driver.name if order.driver else None,
                'progress_percentage': progress_map.get(order.status, 0),
                'total_images': total_images,
                'timeline': tracking_entries,
                'images': images_by_stage
            }

            # -----------------------------
            # ✅ ADD DRIVER DETAILS (ONLY IF EXISTS)
            # -----------------------------
            if order.driver:
                order_data['driver'] = {
                    'id': order.driver.id,
                    'name': order.driver.name,
                    'phone_number': order.driver.phone_number,
                    'email': order.driver.email,
                    'vehicle_number': order.driver.vehicle_number,
                    'identity_url' : order.driver.identity_url,
                    'active': order.driver.active
                }

            orders_data.append(order_data)

        # -----------------------------
        # Final response
        # -----------------------------
        response_data = {
            'success': True,
            'pharmacy_id': pharmacy.id,
            'pharmacy_name': pharmacy.name,
            'total_orders': len(orders_data),
            'orders': orders_data
        }

        return JsonResponse(response_data, encoder=DecimalEncoder, safe=False)

    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {'success': False, 'error': 'Pharmacy not found'},
            status=404
        )

    except Exception as e:
        return JsonResponse(
            {'success': False, 'error': f'An error occurred: {str(e)}'},
            status=500
        )

@csrf_exempt
@require_http_methods(["POST"])
def upload_handover_image_api(request):
    try:
        # Debug logging
        logger.info(f"Upload request received - POST data: {request.POST}")
        logger.info(f"Files in request: {list(request.FILES.keys())}")
        
        # Validate required fields
        if 'image' not in request.FILES:
            logger.error("No image file in request")
            return JsonResponse({
                'success': False,
                'error': 'No image file provided'
            }, status=400)
        
        order_number = request.POST.get('order_number')
        pharmacy_id = request.POST.get('pharmacy_id')
        pharmacy_name = request.POST.get('pharmacy_name')  # Still get for validation but won't use for filename
        driver_id = request.POST.get('driver_id')  # Optional driver ID
        
        logger.info(f"Request params - Order: {order_number}, Pharmacy: {pharmacy_id}, Name: {pharmacy_name}, Driver: {driver_id}")
        
        if not all([order_number, pharmacy_id, pharmacy_name]):
            logger.error("Missing required fields")
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields: order_number, pharmacy_id, pharmacy_name'
            }, status=400)
        
        # Validate pharmacy exists
        try:
            pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)
            logger.info(f"Pharmacy found: {pharmacy.name}")
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
                logger.info(f"Driver found: {driver.name}")
            except Exception as e:
                logger.warning(f"Driver lookup failed for ID {driver_id}: {e}")
                # Don't return error - just proceed without driver
                # This allows pharmacy to upload without assigning a driver
                driver = None
        else:
            logger.info("No driver_id provided or driver_id is empty/null")
        
        # Get the uploaded image
        image_file = request.FILES['image']
        logger.info(f"Image file: {image_file.name}, size: {image_file.size}, type: {image_file.content_type}")
        
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
        
        # Create filename: orderNumber_pharmacyId_pharmacyName_handover
        # Use pharmacy.name from database instead of pharmacy_name from request
        safe_pharmacy_name = "".join(c for c in pharmacy.name if c.isalnum() or c in ('-', '_')).strip()
        filename = f"{order_number}_{pharmacy_id}_{safe_pharmacy_name}_handover{file_extension}"
        blob_name = f"Proof/{filename}"
        
        logger.info(f"Generated filename: {filename}")
        logger.info(f"Blob path: {blob_name}")
        
        # Initialize GCP Storage client
        try:
            from google.cloud import storage
            from google.oauth2 import service_account
            
            logger.info("Initializing Google Cloud Storage client...")
            
            # Define the path to your GCP service account key file
            gcp_key_path = settings.GCP_KEY_PATH
            
            # Check if the key file exists
            if not os.path.exists(gcp_key_path):
                logger.error(f"GCP key file not found at: {gcp_key_path}")
                return JsonResponse({
                    'success': False,
                    'error': 'GCP service account key file not found'
                }, status=500)
            
            # Create credentials from the key file
            credentials = service_account.Credentials.from_service_account_file(settings.GCP_KEY_PATH)
            client = storage.Client(credentials=credentials)
            # bucket = client.bucket('canadrop-bucket')
            bucket = client.bucket(settings.GCP_BUCKET_NAME)
            blob = bucket.blob(blob_name)
            
            logger.info("Google Cloud client initialized successfully")
            
            # Reset file pointer to beginning
            image_file.seek(0)
            
            # Upload the file
            logger.info(f"Starting upload to GCS...")
            blob.upload_from_file(
                image_file,
                content_type=image_file.content_type
            )
            logger.info("Upload to GCS completed")
            
            # Get public URL (works with uniform bucket-level access)
            # The bucket must be configured with appropriate IAM policies for public access
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
        
        # Save OrderImage record
        try:
            order_image = OrderImage.objects.create(
                order=order,
                image_url=public_url,
                stage='handover'
            )
            logger.info(f"OrderImage created with ID: {order_image.id}")
        except Exception as e:
            logger.error(f"Failed to create OrderImage: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to save image record: {str(e)}'
            }, status=500)
        
        # Add tracking entry for handover
        try:
            # Determine who performed the action
            # Since this is pharmacy handover API, performed_by should always be pharmacy
            performed_by = f"Pharmacy: {pharmacy.name}"
            
            tracking_entry = OrderTracking.objects.create(
                order=order,
                pharmacy=pharmacy,
                driver=driver,  # This will be None if no driver_id was provided
                step='handover',
                performed_by=performed_by,
                note=f"Handover image uploaded: {filename}",
                image_url=public_url
            )
            logger.info(f"OrderTracking created with ID: {tracking_entry.id}")
        except Exception as e:
            logger.error(f"Failed to create OrderTracking: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to create tracking entry: {str(e)}'
            }, status=500)
        
        # Update order status to picked_up
        try:
            order.status = 'picked_up'
            order.save()
            logger.info(f"Order status updated to: {order.status}")
        except Exception as e:
            logger.error(f"Failed to update order status: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to update order status: {str(e)}'
            }, status=500)
        
        # Send handover confirmation email to driver
        if driver and driver.email:
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
                logo_url = settings.LOGO_URL
                
                pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

                html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Package Handover Confirmation • CanaLogistiX</title>
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
                           alt="CanaLogistiX"
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
                        Thank you for being a valued Delivery Partner with CanaLogistiX!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Package Handover Confirmation - CanaLogistiX\n\n"
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
                logger.info(f"Handover confirmation email sent to driver: {driver.email}")
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
                'pharmacy_name': pharmacy.name,  # Return actual pharmacy name from database
                'driver_id': driver.id if driver else None,
                'driver_name': driver.name if driver else None,  # Fixed: use driver.name
                'image_url': public_url,
                'filename': filename,
                'order_status': order.status,
                'tracking_entry_id': tracking_entry.id,
                'uploaded_at': order_image.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        logger.error(f"Unexpected error in upload_handover_image_api: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': f'An unexpected error occurred: {str(e)}'
        }, status=500)




@csrf_exempt
@require_http_methods(["POST"])
def driver_login(request):
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        
        # Validate input
        if not email or not password:
            return JsonResponse({
                'success': False,
                'message': 'Email and password are required'
            }, status=400)
        
        # Check if driver exists
        try:
            driver = Driver.objects.get(email=email)
        except Driver.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Invalid credentials'
            }, status=401)
        
        # Validate password
        # If password is hashed, use check_password
        if check_password(password, driver.password):
            password_valid = True
        # If password is plain text (like default "123456"), check directly
        elif driver.password == password:
            password_valid = True
        else:
            password_valid = False
        
        if password_valid:
            return JsonResponse({
                'success': True,
                'id': driver.id,
                'message': 'Login successful'
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid credentials'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON format'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': 'An error occurred during login'
        }, status=500)


# @csrf_exempt
# def get_pending_orders(request):
#     if request.method == "GET":
#         # Fetch all pending orders ordered by created_at (oldest first)
#         orders = DeliveryOrder.objects.filter(status="pending").order_by("created_at")

#         # Prepare JSON data manually
#         data = []
#         for order in orders:
#             data.append({
#                 "id": order.id,
#                 "pharmacy": order.pharmacy.name if order.pharmacy else None,
#                 "driver": order.driver.name if order.driver else None,
#                 "pickup_address": order.pickup_address,
#                 "pickup_city": order.pickup_city,
#                 "pickup_day": order.pickup_day.strftime("%Y-%m-%d"),
#                 "drop_address": order.drop_address,
#                 "drop_city": order.drop_city,
#                 "status": order.status,
#                 "rate": str(order.rate),
#                 "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S"),
#                 "updated_at": order.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
#             })

#         return JsonResponse({"orders": data}, safe=False)

#     return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_pending_orders(request):
    if request.method == "GET":
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

            if pharmacy and pharmacy.business_hours and order.pickup_day:
                # Convert pickup_day to weekday key: Mon, Tue, etc.
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

                "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": order.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

        return JsonResponse({"orders": data}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def assign_driver(request):
    if request.method == "POST":
        try:
            body = json.loads(request.body.decode("utf-8"))
            order_id = body.get("orderId")
            driver_id = body.get("driverId")

            if not order_id or not driver_id:
                return JsonResponse({"error": "orderId and driverId are required"}, status=400)

            # Fetch order & driver
            order = DeliveryOrder.objects.get(id=order_id)
            driver = Driver.objects.get(id=driver_id)

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
                now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
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
    <title>Order Accepted • CanaLogistiX</title>
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
                        alt="CanaLogistiX"
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
                        Drive safe and thank you for being part of the CanaLogistiX team!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    f"Order Accepted - CanaLogistiX\n\n"
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
                    subject=f"Order #{order.id} Accepted • CanaLogistiX Delivery",
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
                now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
                logo_url = settings.LOGO_URL
                
                pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")
                estimated_delivery = "Same day delivery"

                pharmacy_html = f"""\
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Delivery Partner Assigned • CanaLogistiX</title>
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
                                <img src="{logo_url}" alt="CanaLogistiX" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
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
                                    Thank you for trusting CanaLogistiX with your deliveries!
                                </p>
                                </td>
                            </tr>
                            </table>
                        </td>
                        </tr>

                    </table>
                    
                    <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
                        © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
                    </p>
                    </td>
                </tr>
                </table>
            </body>
            </html>
            """
                pharmacy_text = (
                    f"Delivery Partner Assigned - CanaLogistiX\n\n"
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
                    subject=f"Delivery Partner Assigned to Order #{order.id} • CanaLogistiX",
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

    return JsonResponse({"error": "Invalid request method"}, status=405)



@csrf_exempt
def get_driver_details(request):
    if request.method == "GET":
        driver_id = request.GET.get("driverId")

        if not driver_id:
            return JsonResponse({"error": "driverId is required"}, status=400)

        try:
            driver = Driver.objects.get(id=driver_id)
            return JsonResponse({
                "id": driver.id,
                "name": driver.name,
                "phone_number" : driver.phone_number,
                "vehicle_number" : driver.vehicle_number,
                "active" : driver.active,
                "email": driver.email,
                "identity_url" : driver.identity_url
            }, status=200)
        except Driver.DoesNotExist:
            return JsonResponse({"error": "Driver not found"}, status=404)

    return JsonResponse({"error": "Invalid request method"}, status=405)




# @csrf_exempt
# def driver_accepted_orders(request):
#     if request.method != "GET":
#         return HttpResponseBadRequest("Only GET requests are allowed")

#     driver_id = request.GET.get("driverId")
#     if not driver_id:
#         return HttpResponseBadRequest("Missing required parameter: driverId")

#     try:
#         driver_id = int(driver_id)
#     except (ValueError, TypeError):
#         return HttpResponseBadRequest("driverId must be an integer")

#     qs = DeliveryOrder.objects.filter(
#         driver_id=driver_id,
#         status__in=["accepted", "picked_up", "inTransit"]
#     ).select_related("pharmacy")

#     orders = []
#     for o in qs:
#         # ----------------------------
#         # Distance calculation
#         # ----------------------------
#         distance_km = 0
#         if o.pickup_address and o.pickup_city and o.drop_address and o.drop_city:
#             calculated_distance, error = get_distance_km(
#                 o.pickup_address,
#                 o.pickup_city,
#                 o.drop_address,
#                 o.drop_city
#             )
#             if calculated_distance is not None:
#                 distance_km = calculated_distance

#         # ----------------------------
#         # Store hours for pickup day
#         # ----------------------------
#         store_hours_for_day = None
#         if o.pharmacy and o.pickup_day:
#             day_key = o.pickup_day.strftime("%a")  # Mon, Tue, Wed...
#             store_hours_for_day = o.pharmacy.business_hours.get(day_key)

#         orders.append({
#             "id": o.id,
#             "pharmacy_id": o.pharmacy_id,
#             "pharmacy_name": getattr(o.pharmacy, "name", None),

#             # ✅ NEW: only pickup-day hours
#             "store_hours_for_pickup_day": store_hours_for_day,

#             "customer_name": o.customer_name,
#             "customer_phone": o.customer_phone,
#             "driver_id": o.driver_id,
#             "pickup_address": o.pickup_address,
#             "pickup_city": o.pickup_city,
#             "pickup_day": o.pickup_day.isoformat() if o.pickup_day else None,
#             "drop_address": o.drop_address,
#             "drop_city": o.drop_city,
#             "status": o.status,
#             "rate": float(o.rate) if isinstance(o.rate, Decimal) else o.rate,
#             "distance_km": round(distance_km, 2),
#             "created_at": o.created_at.isoformat() if o.created_at else None,
#             "updated_at": o.updated_at.isoformat() if o.updated_at else None,
#         })

#     return JsonResponse({"orders": orders})


@csrf_exempt
def driver_accepted_orders(request):
    if request.method != "GET":
        return HttpResponseBadRequest("Only GET requests are allowed")

    driver_id = request.GET.get("driverId")
    if not driver_id:
        return HttpResponseBadRequest("Missing required parameter: driverId")

    try:
        driver_id = int(driver_id)
    except (ValueError, TypeError):
        return HttpResponseBadRequest("driverId must be an integer")

    qs = DeliveryOrder.objects.filter(
        driver_id=driver_id,
        status__in=["accepted", "picked_up", "inTransit"]
    ).select_related("pharmacy")

    orders = []
    for o in qs:
        # Distance calculation
        distance_km = 0
        if o.pickup_address and o.pickup_city and o.drop_address and o.drop_city:
            calculated_distance, error = get_distance_km(
                o.pickup_address,
                o.pickup_city,
                o.drop_address,
                o.drop_city
            )
            if calculated_distance is not None:
                distance_km = calculated_distance

        # Store hours for pickup day
        store_hours_for_day = None
        if o.pharmacy and o.pickup_day:
            day_key = o.pickup_day.strftime("%a")  # Mon, Tue, Wed...
            store_hours_for_day = o.pharmacy.business_hours.get(day_key)

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
            "distance_km": round(distance_km, 2),
            
            # ✅ NEW FIELDS
            "signature_required": o.signature_required,
            "id_verification_required": o.id_verification_required,
            "alternate_contact": o.alternate_contact,
            "delivery_notes": o.delivery_notes,
            "signature_ack_url": o.signature_ack_url,
            "id_verified" : o.id_verified,
            
            "created_at": o.created_at.isoformat() if o.created_at else None,
            "updated_at": o.updated_at.isoformat() if o.updated_at else None,
        })

    return JsonResponse({"orders": orders})
    

@csrf_exempt
def driver_pickup_proof(request):
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST method allowed")

    driver_id = request.POST.get("driverId")
    order_id = request.POST.get("orderId")
    pharmacy_id = request.POST.get("pharmacyId")
    image_file = request.FILES.get("image")

    if not (driver_id and order_id and pharmacy_id and image_file):
        return HttpResponseBadRequest("driverId, orderId, pharmacyId and image are required")

    try:
        # fetch objects
        driver = get_object_or_404(Driver, id=driver_id)
        order = get_object_or_404(DeliveryOrder, id=order_id)
        pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

        # step 1: update order status to inTransit
        order.status = "inTransit"
        order.save()

        # step 2: upload image to GCP
        key_path = settings.GCP_KEY_PATH
        # bucket_name = "canadrop-bucket"  # Fixed bucket name
        bucket_name = settings.GCP_BUCKET_NAME  # Fixed bucket name

        client = storage.Client.from_service_account_json(key_path)
        bucket = client.bucket(bucket_name)

        safe_pharmacy_name = pharmacy.name.replace(" ", "_")
        filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_driverpickup.jpg"
        blob_name = f"Proof/{filename}"
        blob = bucket.blob(blob_name)
        blob.upload_from_file(image_file, content_type=image_file.content_type)

        # get public URL
        public_url = f"https://storage.googleapis.com/{bucket_name}/{blob_name}"

        # step 3a: create order tracking entry
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

        # step 3b: create order image entry
        OrderImage.objects.create(
            order=order,
            image_url=public_url,
            stage="pickup"
        )

        # ---- Send pickup proof notification email to pharmacy ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
            logo_url = settings.LOGO_URL
            
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

            html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Picked Up • CanaLogistiX</title>
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
                        alt="CanaLogistiX"
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
                        {driver.vehicle_number or 'N/A'}
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
                        Thank you for trusting CanaLogistiX with your deliveries!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                f"Order Picked Up - CanaLogistiX\n\n"
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
                f"- Vehicle Number: {driver.vehicle_number or 'N/A'}\n\n"
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
        except Exception:
            pass

        return JsonResponse({
            "success": True,
            "message": "Pickup proof uploaded successfully",
            "image_url": public_url
        })

    except Exception as e:
        return JsonResponse({
            "success": False,
            "message": f"Error uploading pickup proof: {str(e)}"
        }, status=500)



@csrf_exempt
def driver_delivery_proof(request):
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST method allowed")

    driver_id = request.POST.get("driverId")
    order_id = request.POST.get("orderId")
    pharmacy_id = request.POST.get("pharmacyId")
    image_file = request.FILES.get("image")

    if not (driver_id and order_id and pharmacy_id and image_file):
        return HttpResponseBadRequest("driverId, orderId, pharmacyId and image are required")

    try:
        # fetch objects
        driver = get_object_or_404(Driver, id=driver_id)
        order = get_object_or_404(DeliveryOrder, id=order_id)
        pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

        # step 1: update order status to delivered
        order.status = "delivered"
        order.is_delivered = True
        order.delivered_at = timezone.now()
        order.save()

        # step 2: upload image to GCP
        key_path = settings.GCP_KEY_PATH
        # bucket_name = "canadrop-bucket"  # Fixed bucket name
        bucket_name = settings.GCP_BUCKET_NAME  # Fixed bucket name

        client = storage.Client.from_service_account_json(key_path)
        bucket = client.bucket(bucket_name)

        safe_pharmacy_name = pharmacy.name.replace(" ", "_")
        filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_delivered.jpg"
        blob_name = f"Proof/{filename}"
        blob = bucket.blob(blob_name)
        blob.upload_from_file(image_file, content_type=image_file.content_type)

        # get public URL
        public_url = f"https://storage.googleapis.com/{bucket_name}/{blob_name}"

        # step 3a: order tracking entry
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

        # step 3b: order image entry
        OrderImage.objects.create(
            order=order,
            image_url=public_url,
            stage="delivered"
        )

        try:
            # Award 50 points to the driver
            driver_cc_account, created = CCPointsAccount.objects.get_or_create(
                driver=driver,
                defaults={'points_balance': 0}
            )
            driver_cc_account.points_balance += int(settings.CC_POINTS_PER_ORDER)
            driver_cc_account.save()

            # Award 50 points to the pharmacy
            pharmacy_cc_account, created = CCPointsAccount.objects.get_or_create(
                pharmacy=pharmacy,
                defaults={'points_balance': 0}
            )
            pharmacy_cc_account.points_balance += int(settings.CC_POINTS_PER_ORDER)
            pharmacy_cc_account.save()

        except Exception as e:
            # Log the error but don't fail the delivery process
            print(f"Error awarding CC Points: {str(e)}")
            pass

        # ---- Send delivery confirmation email to pharmacy ----
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
            logo_url = settings.LOGO_URL
            
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y")

            html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Delivered • CanaLogistiX</title>
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
                        alt="CanaLogistiX"
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
                        {driver.vehicle_number or 'N/A'}
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
                    🎉 <strong>Delivery Complete!</strong> Thank you for using CanaLogistiX for your delivery needs.
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
                        Thank you for trusting CanaLogistiX with your deliveries!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                f"Order Delivered - CanaLogistiX\n\n"
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
                f"- Vehicle Number: {driver.vehicle_number or 'N/A'}\n\n"
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
        except Exception:
            pass

        return JsonResponse({
            "success": True,
            "message": "Delivery proof uploaded successfully",
            "image_url": public_url
        })

    except Exception as e:
        return JsonResponse({
            "success": False,
            "message": f"Error uploading delivery proof: {str(e)}"
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
    blob = bucket.blob(f"PharmacyInvoices/{filename}")
    pdf_buffer.seek(0)
    blob.upload_from_file(pdf_buffer, content_type="application/pdf")
    # bucket is public → public URL ok; or use signed URL if you prefer
    return f"https://storage.googleapis.com/canadrop-bucket/PharmacyInvoices/{filename}"



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
    invoice_number = f"INV-PH-{invoice.id:06d}"
    
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
    <b><font color="#0F172A" size="11">CanaLogistiX Delivery Services</font></b><br/>
    <font color="#64748B" size="9">Cana Group of Companies<br/>
    Operating Name of CANABELLE INC.<br/>
    BN: 758568562<br/>
    help.canalogistix@gmail.com</font>
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
        ['HST (13%)', f"${hst_amount:.2f}"],
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
    <b>Payment Due Date:</b> Payment is due within 2 business days of invoice issue date. The due date for this invoice is <b>{due_date_formatted}</b>. Late payments will incur penalties as outlined below.<br/><br/>
    
    <b>Late Payment Penalties:</b> Failure to remit payment by the due date will result in a late payment fee of 5% of the outstanding balance, applied immediately upon default. An additional interest charge of 2% per month (26.8% annually) will be applied to all overdue amounts until paid in full.<br/><br/>
    
    <b>Service Suspension:</b> Accounts with payments overdue by more than 5 business days may be subject to temporary suspension of delivery services until all outstanding balances are settled. CanaLogistiX reserves the right to suspend service without prior notice for non-payment.<br/><br/>
    
    <b>Payment Method:</b> Payments should be made via electronic funds transfer (EFT), credit card, or company check. Please include the invoice number as reference when making payment. For EFT details, contact our accounts department.<br/><br/>
    
    <b>Service Description:</b> This invoice covers pharmaceutical delivery services provided during the billing period. All deliveries were completed by trained, licensed drivers following strict chain-of-custody protocols for pharmaceutical products.<br/><br/>
    
    <b>Tax Information:</b> All amounts include applicable HST (13%) as required by Ontario tax regulations. CanaLogistiX HST Registration Number available upon request.<br/><br/>
    
    <b>Dispute Resolution:</b> Any billing disputes must be submitted in writing within 5 business days of invoice receipt. Undisputed portions of the invoice remain due by the stated due date.
    '''
    
    story.append(Paragraph(terms_text, body_style))
    story.append(Spacer(1, 30))
    
    # ==================== PAYMENT INSTRUCTIONS ====================
    
    story.append(Paragraph("Payment Instructions", section_header_style))
    
    payment_instructions = '''
    <b>Method 1 - Electronic Funds Transfer (Preferred):</b><br/>
    Contact our accounts team at help.canalogistix@gmail.com to obtain secure EFT payment details. Please include your pharmacy name and invoice number in the transfer notes.<br/><br/>
    
    <b>Method 2 - Credit Card Payment:</b><br/>
    Log in to your pharmacy portal at CanaLogistiX and navigate to the Billing section to pay securely online with credit card.<br/><br/>
    
    <b>Method 3 - Company Check:</b><br/>
    Make checks payable to "CanaLogistiX - Cana Group of Companies" and mail to:<br/>
    12 - 147 Fairway Road North, Kitchener, N2A 2N4, Ontario, Canada<br/>
    Include invoice number on check memo line.
    '''
    
    story.append(Paragraph(payment_instructions, body_style))
    story.append(Spacer(1, 30))
    
    # ==================== QUESTIONS OR CONCERNS ====================
    
    story.append(Paragraph("Questions or Concerns?", section_header_style))
    
    support_text = '''
    Our billing and support team is available to assist with any questions about this invoice or your delivery services. We're committed to providing exceptional service and transparent billing.<br/><br/>
    <b>Email:</b> help.canalogistix@gmail.com<br/>
    <b>Phone:</b> Available through pharmacy portal<br/>
    <b>Support Hours:</b> Monday - Friday, 9:00 AM - 6:00 PM EST<br/>
    <b>Response Time:</b> Within 24 business hours for billing inquiries<br/><br/>
    <b>For Billing Disputes:</b> Please submit all disputes in writing via email with supporting documentation within 5 business days of receiving this invoice.
    '''
    
    story.append(Paragraph(support_text, body_style))
    story.append(Spacer(1, 40))
    
    # ==================== FOOTER ====================
    
    footer_text = f'''
    <i>This invoice was automatically generated by CanaLogistiX billing system on {current_date}.<br/>
    Invoice Reference: {invoice_number} | Payment Due: {due_date_formatted}<br/>
    Thank you for choosing CanaLogistiX for your pharmaceutical delivery needs!<br/>
    © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.</i>
    '''
    
    story.append(Paragraph(footer_text, footer_style))
    
    # Build PDF
    doc.build(story)
    
    logger.info(f"Generated PDF for invoice {invoice.id}")
    return buffer

@csrf_exempt
def generate_weekly_invoices(request):
    pharmacy_id = request.GET.get("pharmacyId")
    if not pharmacy_id:
        return HttpResponseBadRequest("Missing pharmacyId parameter")

    try:
        pharmacy_id = int(pharmacy_id)
    except ValueError:
        return HttpResponseBadRequest("pharmacyId must be an integer")

    pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)
    logger.info(f"Generating weekly invoices for pharmacy {pharmacy.name} (ID: {pharmacy_id})")

    # Only delivered orders for this pharmacy
    orders_qs = DeliveryOrder.objects.filter(
        pharmacy_id=pharmacy_id,
        status="delivered"
    ).order_by("created_at")

    if not orders_qs.exists():
        logger.info(f"No delivered orders found for pharmacy {pharmacy.name} (ID: {pharmacy_id})")
        return JsonResponse({"message": "No delivered orders for this pharmacy yet", "invoices": []})

    earliest = orders_qs.first().created_at.date()
    latest = orders_qs.last().created_at.date()

    # Get current date/time in Toronto timezone
    toronto_now = timezone.now().astimezone(settings.USER_TIMEZONE)
    today = toronto_now.date()
    
    invoices_list = []
    week_start = earliest

    # Only process completed weeks (7 days: start and end day both included)
    while week_start <= latest:
        week_end = week_start + timedelta(days=6)  # 7-day week: start + 6 days = 7 total days
        
        # Skip this week if it hasn't completed yet
        # Week is complete only when we're past 23:59:59 of week_end day (i.e., into the next day)
        # Since we're comparing dates, week is complete when today > week_end
        if week_end >= today:
            logger.info(f"Skipping incomplete week {week_start} to {week_end} (today is {today} in America/Toronto timezone)")
            break  # No more complete weeks after this
        
        # Adjust week_end to not exceed latest order date
        week_end = min(week_end, latest)

        # Filter orders only in this week and delivered
        week_orders = orders_qs.filter(
            created_at__date__gte=week_start,
            created_at__date__lte=week_end
        )
        total_orders = week_orders.count()

        if total_orders > 0:
            logger.debug(f"Processing completed week {week_start} to {week_end} with {total_orders} orders")

            # Calculate subtotal, HST, and final total
            subtotal = sum(Decimal(str(o.rate)) for o in week_orders)
            hst_rate = Decimal('0.13')  # 13% HST
            hst_amount = (subtotal * hst_rate)
            total_amount_with_hst = (subtotal + hst_amount)

            due_date = week_end + timedelta(days=2)  # due date 2 days after end_date

            # get or create invoice
            invoice, created = Invoice.objects.get_or_create(
                pharmacy=pharmacy,
                start_date=week_start,
                end_date=week_end,
                defaults={
                    "total_orders": total_orders,
                    "total_amount": total_amount_with_hst,  # Store final amount including HST
                    "due_date": due_date,
                    "status": "generated"
                }
            )

            if created:
                logger.info(f"Created new invoice {invoice.id} for pharmacy {pharmacy.name}")
            else:
                logger.debug(f"Updated existing invoice {invoice.id} for pharmacy {pharmacy.name}")
                # Keep totals up to date
                invoice.total_orders = total_orders
                invoice.total_amount = total_amount_with_hst
                invoice.due_date = due_date
                if invoice.status is None:
                    invoice.status = "generated"
                invoice.save()

            # Build order rows for the PDF
            orders_data = [{
                "order_id": o.id,
                "pickup_address": o.pickup_address,
                "pickup_city": o.pickup_city,
                "drop_address": o.drop_address,
                "drop_city": o.drop_city,
                "pickup_day": o.pickup_day.strftime('%Y-%m-%d'),
                "rate": float(o.rate),
                "created_at": o.created_at.strftime('%Y-%m-%d %H:%M'),
                "driver": o.driver.name if o.driver else "N/A"
            } for o in week_orders]

            # Determine whether we must (re)generate/upload the PDF
            pdf_url = invoice.pdf_url or ""
            needs_upload = (
                not pdf_url                                         # missing
                or pdf_url.startswith("/")                          # local temp path like "/temp_..."
                or pdf_url.startswith("/media/")                    # local media path
            )

            if needs_upload:
                try:
                    # Generate PDF buffer
                    pdf_buffer = generate_invoice_pdf(
                        invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount_with_hst
                    )

                    # Create filename: pharmacyId_PharmacyName_StartDate_EndDate.pdf
                    pharmacy_name_clean = pharmacy.name.replace(' ', '_').replace('/', '_').replace('\\', '_')
                    start_date_str = invoice.start_date.strftime('%Y-%m-%d')
                    end_date_str = invoice.end_date.strftime('%Y-%m-%d')
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{invoice.id}_{pharmacy.name}_{invoice.start_date}_{invoice.end_date}_{timestamp}.pdf"

                    # Require GCS upload to succeed; NO local fallback
                    uploaded_url = upload_pdf_to_gcp(pdf_buffer, filename)
                    if not uploaded_url:
                        logger.error(f"GCS upload returned empty URL for invoice {invoice.id}")
                        return JsonResponse(
                            {"error": f"Failed to upload invoice PDF for invoice {invoice.id}"},
                            status=500
                        )

                    invoice.pdf_url = uploaded_url
                    invoice.save()
                    pdf_url = uploaded_url
                    logger.info(f"Successfully generated and uploaded PDF for invoice {invoice.id}")

                except Exception as e:
                    logger.exception(f"Error generating/uploading PDF for invoice {invoice.id}: {e}")
                    return JsonResponse(
                        {"error": f"Error generating/uploading PDF for invoice {invoice.id}: {str(e)}"},
                        status=500
                    )
            else:
                logger.debug(f"Using existing PDF URL for invoice {invoice.id}")

            # Send invoice notification email to pharmacy
            if created and pharmacy.email:  # Only send email for newly created invoices
                try:
                    brand_primary = settings.BRAND_COLORS['primary']
                    brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                    brand_accent = settings.BRAND_COLORS['accent']
                    now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
                    logo_url = settings.LOGO_URL
                    
                    start_date_formatted = invoice.start_date.strftime("%B %d, %Y")
                    end_date_formatted = invoice.end_date.strftime("%B %d, %Y")
                    due_date_formatted = invoice.due_date.strftime("%B %d, %Y")

                    # Using .format() to avoid f-string CSS brace conflicts
                    invoice_html = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Invoice Generated • CanaLogistiX</title>
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
                      <img src="{logo_url}" alt="CanaLogistiX" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
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
                        Thank you for choosing CanaLogistiX for your delivery needs!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {current_year} CanaLogistiX - Cana Group of Companies. All rights reserved.
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
                        current_year=timezone.now().year
                    )

                    invoice_text = (
                        f"Invoice Generated - CanaLogistiX\n\n"
                        f"Hello {pharmacy.name},\n\n"
                        f"Your invoice for the week of {start_date_formatted} to {end_date_formatted} has been generated.\n\n"
                        f"Invoice #{invoice.id}\n"
                        f"Total Amount: ${total_amount_with_hst:.2f}\n"
                        f"Payment Due: {due_date_formatted}\n\n"
                        f"{total_orders} deliveries completed during this period.\n\n"
                        f"IMPORTANT: Payment due by {due_date_formatted} to avoid penalties or service interruptions.\n\n"
                        f"Download your invoice: {pdf_url}\n\n"
                        f"For complete invoice details, payment history, and delivery breakdowns, please visit the Invoices Section in your pharmacy portal.\n\n"
                        f"For payment inquiries, contact billing at {settings.EMAIL_BILLING}\n"
                    )

                    _send_html_email_billing(
                        subject=f"Invoice #{invoice.id} Generated • Week of {start_date_formatted}",
                        to_email=pharmacy.email,
                        html=invoice_html,
                        text_fallback=invoice_text,
                    )
                    logger.info(f"Invoice notification email sent to {pharmacy.email} for invoice {invoice.id}")
                    
                except Exception as e:
                    logger.error(f"ERROR sending invoice email to {pharmacy.email}: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    # Don't fail the invoice generation if email fails

            invoices_list.append({
                "invoice_id": invoice.id,
                "start_date": invoice.start_date.strftime('%Y-%m-%d'),
                "end_date": invoice.end_date.strftime('%Y-%m-%d'),
                "total_orders": invoice.total_orders,
                "subtotal": float(subtotal),
                "hst_amount": float(hst_amount),
                "total_amount": float(invoice.total_amount),
                "due_date": invoice.due_date.strftime('%Y-%m-%d'),
                "status": invoice.status,
                "pdf_url": pdf_url,
                "orders": orders_data
            })

        # Move to next week window
        week_start += timedelta(days=7)

    logger.info(f"Generated {len(invoices_list)} invoices for pharmacy {pharmacy.name}")
    return JsonResponse({"invoices": invoices_list})


# @csrf_exempt
# def generate_weekly_invoices(request):
#     pharmacy_id = request.GET.get("pharmacyId")
#     if not pharmacy_id:
#         return HttpResponseBadRequest("Missing pharmacyId parameter")

#     try:
#         pharmacy_id = int(pharmacy_id)
#     except ValueError:
#         return HttpResponseBadRequest("pharmacyId must be an integer")

#     pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)
#     logger.info(f"Generating weekly invoices for pharmacy {pharmacy.name} (ID: {pharmacy_id})")

#     # Only delivered orders for this pharmacy
#     orders_qs = DeliveryOrder.objects.filter(
#         pharmacy_id=pharmacy_id,
#         status="delivered"
#     ).order_by("created_at")

#     if not orders_qs.exists():
#         logger.info(f"No delivered orders found for pharmacy {pharmacy.name} (ID: {pharmacy_id})")
#         return JsonResponse({"message": "No delivered orders for this pharmacy yet", "invoices": []})

#     earliest = orders_qs.first().created_at.date()
#     latest = orders_qs.last().created_at.date()

#     invoices_list = []
#     week_start = earliest

#     # Include current partial week
#     while week_start <= latest:
#         week_end = min(week_start + timedelta(days=6), latest)

#         # Filter orders only in this week and delivered
#         week_orders = orders_qs.filter(
#             created_at__date__gte=week_start,
#             created_at__date__lte=week_end
#         )
#         total_orders = week_orders.count()

#         if total_orders > 0:
#             logger.debug(f"Processing week {week_start} to {week_end} with {total_orders} orders")

#             # Calculate subtotal, HST, and final total
#             subtotal = sum(Decimal(str(o.rate)) for o in week_orders)
#             hst_rate = Decimal('0.13')  # 13% HST
#             hst_amount = (subtotal * hst_rate)
#             total_amount_with_hst = (subtotal + hst_amount)

#             due_date = week_end + timedelta(days=2)  # due date 2 days after end_date

#             # get or create invoice
#             invoice, created = Invoice.objects.get_or_create(
#                 pharmacy=pharmacy,
#                 start_date=week_start,
#                 end_date=week_end,
#                 defaults={
#                     "total_orders": total_orders,
#                     "total_amount": total_amount_with_hst,  # Store final amount including HST
#                     "due_date": due_date,
#                     "status": "generated"
#                 }
#             )

#             if created:
#                 logger.info(f"Created new invoice {invoice.id} for pharmacy {pharmacy.name}")
#             else:
#                 logger.debug(f"Updated existing invoice {invoice.id} for pharmacy {pharmacy.name}")
#                 # Keep totals up to date
#                 invoice.total_orders = total_orders
#                 invoice.total_amount = total_amount_with_hst
#                 invoice.due_date = due_date
#                 if invoice.status is None:
#                     invoice.status = "generated"
#                 invoice.save()

#             # Build order rows for the PDF
#             orders_data = [{
#                 "order_id": o.id,
#                 "pickup_address": o.pickup_address,
#                 "pickup_city": o.pickup_city,
#                 "drop_address": o.drop_address,
#                 "drop_city": o.drop_city,
#                 "pickup_day": o.pickup_day.strftime('%Y-%m-%d'),
#                 "rate": float(o.rate),
#                 "created_at": o.created_at.strftime('%Y-%m-%d %H:%M'),
#                 "driver": o.driver.name if o.driver else "N/A"
#             } for o in week_orders]

#             # Determine whether we must (re)generate/upload the PDF
#             pdf_url = invoice.pdf_url or ""
#             needs_upload = (
#                 not pdf_url                                         # missing
#                 or pdf_url.startswith("/")                          # local temp path like "/temp_..."
#                 or pdf_url.startswith("/media/")                    # local media path
#             )

#             if needs_upload:
#                 try:
#                     # Generate PDF buffer
#                     pdf_buffer = generate_invoice_pdf(
#                         invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount_with_hst
#                     )

#                     # Create filename: pharmacyId_PharmacyName_StartDate_EndDate.pdf
#                     pharmacy_name_clean = pharmacy.name.replace(' ', '_').replace('/', '_').replace('\\', '_')
#                     start_date_str = invoice.start_date.strftime('%Y-%m-%d')
#                     end_date_str = invoice.end_date.strftime('%Y-%m-%d')
#                     timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
#                     filename = f"{invoice.id}_{pharmacy.name}_{invoice.start_date}_{invoice.end_date}_{timestamp}.pdf"

#                     # Require GCS upload to succeed; NO local fallback
#                     uploaded_url = upload_pdf_to_gcp(pdf_buffer, filename)
#                     if not uploaded_url:
#                         logger.error(f"GCS upload returned empty URL for invoice {invoice.id}")
#                         return JsonResponse(
#                             {"error": f"Failed to upload invoice PDF for invoice {invoice.id}"},
#                             status=500
#                         )

#                     invoice.pdf_url = uploaded_url
#                     invoice.save()
#                     pdf_url = uploaded_url
#                     logger.info(f"Successfully generated and uploaded PDF for invoice {invoice.id}")

#                 except Exception as e:
#                     logger.exception(f"Error generating/uploading PDF for invoice {invoice.id}: {e}")
#                     return JsonResponse(
#                         {"error": f"Error generating/uploading PDF for invoice {invoice.id}: {str(e)}"},
#                         status=500
#                     )
#             else:
#                 logger.debug(f"Using existing PDF URL for invoice {invoice.id}")

#             # Send invoice notification email to pharmacy
#             if created and pharmacy.email:  # Only send email for newly created invoices
#                 try:
#                     brand_primary = settings.BRAND_COLORS['primary']
#                     brand_primary_dark = settings.BRAND_COLORS['primary_dark']
#                     brand_accent = settings.BRAND_COLORS['accent']
#                     now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
#                     logo_url = settings.LOGO_URL
                    
#                     start_date_formatted = invoice.start_date.strftime("%B %d, %Y")
#                     end_date_formatted = invoice.end_date.strftime("%B %d, %Y")
#                     due_date_formatted = invoice.due_date.strftime("%B %d, %Y")

#                     # Using .format() to avoid f-string CSS brace conflicts
#                     invoice_html = """
# <!doctype html>
# <html lang="en">
#   <head>
#     <meta charset="utf-8">
#     <title>Invoice Generated • CanaLogistiX</title>
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
#     <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f7f9;padding:24px 12px;">
#       <tr>
#         <td align="center">
#           <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="card" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
#             <tr>
#               <td style="background:{brand_primary};padding:18px 20px;">
#                 <table width="100%" cellspacing="0" cellpadding="0" border="0">
#                   <tr>
#                     <td align="left">
#                       <img src="{logo_url}" alt="CanaLogistiX" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
#                     </td>
#                     <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
#                       Invoice Generated
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>
            
#             <tr>
#               <td style="padding:28px 24px 6px;">
#                 <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                   Your weekly invoice is ready
#                 </h1>
#                 <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
#                   Hello <strong>{pharmacy_name}</strong>, your invoice for the week of <strong>{start_date_formatted}</strong> to <strong>{end_date_formatted}</strong> has been generated.
#                 </p>
                
#                 <div style="margin:18px 0;background:#eff6ff;border:1px solid #3b82f6;border-radius:12px;padding:14px 18px;">
#                   <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#1e40af;">
#                     📄 Invoice #{invoice_id} — Payment due by <strong>{due_date_formatted}</strong>
#                   </p>
#                 </div>
                
#                 <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
#                   <p style="margin:0 0 8px;font:700 15px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                     📊 Quick Summary
#                   </p>
#                   <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
#                     <strong>{total_orders} deliveries</strong> completed from {start_date_formatted} to {end_date_formatted}.
#                   </p>
#                   <p style="margin:8px 0 0;font:700 16px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{brand_primary};">
#                     Total Amount: ${total_amount:.2f}
#                   </p>
#                 </div>
                
#                 <div style="margin:18px 0;text-align:center;">
#                   <a href="{pdf_url}" 
#                      style="display:inline-block;background:{brand_primary};color:#ffffff;text-decoration:none;padding:12px 32px;border-radius:8px;font:600 14px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;margin-bottom:12px;">
#                     📥 Download Invoice PDF
#                   </a>
#                 </div>
                
#                 <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;text-align:center;">
#                   <p style="margin:0 0 8px;font:600 14px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
#                     📋 View Full Invoice Details
#                   </p>
#                   <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
#                     For a complete breakdown of charges, payment history, and delivery details, please visit the <strong>Invoices Section</strong> in your pharmacy portal.
#                   </p>
#                 </div>
                
#                 <div style="margin:18px 0;background:#fef2f2;border-left:3px solid #ef4444;border-radius:8px;padding:14px 16px;">
#                   <p style="margin:0;font:600 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#7f1d1d;">
#                     ⚠️ Payment due by <strong>{due_date_formatted}</strong> to avoid penalties or service interruptions.
#                   </p>
#                 </div>
                
#                 <p style="margin:18px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
#                   Invoice generated on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
#                 </p>
                
#                 <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
#                 <p class="muted" style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
#                   For payment inquiries or invoice questions, Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.
#                 </p>
#               </td>
#             </tr>
            
#             <tr>
#               <td style="padding:0 24px 24px;">
#                 <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;">
#                   <tr>
#                     <td style="padding:12px 16px;">
#                       <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
#                         Thank you for choosing CanaLogistiX for your delivery needs!
#                       </p>
#                     </td>
#                   </tr>
#                 </table>
#               </td>
#             </tr>

#           </table>
          
#           <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
#             © {current_year} CanaLogistiX - Cana Group of Companies. All rights reserved.
#           </p>
#         </td>
#       </tr>
#     </table>
#   </body>
# </html>
# """.format(
#                         brand_primary=brand_primary,
#                         brand_primary_dark=brand_primary_dark,
#                         logo_url=logo_url,
#                         pharmacy_name=pharmacy.name,
#                         start_date_formatted=start_date_formatted,
#                         end_date_formatted=end_date_formatted,
#                         invoice_id=invoice.id,
#                         due_date_formatted=due_date_formatted,
#                         total_orders=total_orders,
#                         total_amount=float(total_amount_with_hst),
#                         pdf_url=pdf_url,
#                         now_str=now_str,
#                         current_year=timezone.now().year
#                     )

#                     invoice_text = (
#                         f"Invoice Generated - CanaLogistiX\n\n"
#                         f"Hello {pharmacy.name},\n\n"
#                         f"Your invoice for the week of {start_date_formatted} to {end_date_formatted} has been generated.\n\n"
#                         f"Invoice #{invoice.id}\n"
#                         f"Total Amount: ${total_amount_with_hst:.2f}\n"
#                         f"Payment Due: {due_date_formatted}\n\n"
#                         f"{total_orders} deliveries completed during this period.\n\n"
#                         f"IMPORTANT: Payment due by {due_date_formatted} to avoid penalties or service interruptions.\n\n"
#                         f"Download your invoice: {pdf_url}\n\n"
#                         f"For complete invoice details, payment history, and delivery breakdowns, please visit the Invoices Section in your pharmacy portal.\n\n"
#                         f"For payment inquiries, contact billing at {settings.EMAIL_BILLING}\n"
#                     )

#                     _send_html_email_billing(
#                         subject=f"Invoice #{invoice.id} Generated • Week of {start_date_formatted}",
#                         to_email=pharmacy.email,
#                         html=invoice_html,
#                         text_fallback=invoice_text,
#                     )
#                     logger.info(f"Invoice notification email sent to {pharmacy.email} for invoice {invoice.id}")
                    
#                 except Exception as e:
#                     logger.error(f"ERROR sending invoice email to {pharmacy.email}: {str(e)}")
#                     import traceback
#                     traceback.print_exc()
#                     # Don't fail the invoice generation if email fails

#             invoices_list.append({
#                 "invoice_id": invoice.id,
#                 "start_date": invoice.start_date.strftime('%Y-%m-%d'),
#                 "end_date": invoice.end_date.strftime('%Y-%m-%d'),
#                 "total_orders": invoice.total_orders,
#                 "subtotal": float(subtotal),
#                 "hst_amount": float(hst_amount),
#                 "total_amount": float(invoice.total_amount),
#                 "due_date": invoice.due_date.strftime('%Y-%m-%d'),
#                 "status": invoice.status,
#                 "pdf_url": pdf_url,
#                 "orders": orders_data
#             })

#         # Move to next week window
#         week_start += timedelta(days=7)

#     logger.info(f"Generated {len(invoices_list)} invoices for pharmacy {pharmacy.name}")
#     return JsonResponse({"invoices": invoices_list})



# Set Stripe API key
stripe.api_key = settings.STRIPE_SECRET_KEY

@csrf_exempt  # CSRF exempt as requested
@require_http_methods(["POST"])
def create_checkout_session(request):
    """Create Stripe checkout session for invoice payment"""
    logger.info("=== CREATE CHECKOUT SESSION STARTED ===")
    
    try:
        # Log request details
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request headers: {dict(request.headers)}")
        logger.info(f"Request body: {request.body.decode('utf-8')}")
        
        # Parse JSON data
        try:
            data = json.loads(request.body)
            logger.info(f"Parsed data: {data}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        
        invoice_id = data.get('invoice_id')
        pharmacy_id = data.get('pharmacy_id')
        
        logger.info(f"Invoice ID: {invoice_id} (type: {type(invoice_id)})")
        logger.info(f"Pharmacy ID: {pharmacy_id} (type: {type(pharmacy_id)})")
        
        # Validate required fields
        if not invoice_id or not pharmacy_id:
            logger.error("Missing invoice_id or pharmacy_id")
            return JsonResponse({'error': 'invoice_id and pharmacy_id are required'}, status=400)
        
        # Convert to integers if they're strings
        try:
            invoice_id = int(invoice_id)
            pharmacy_id = int(pharmacy_id)
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
    <title>Payment Confirmation • CanaLogistiX</title>
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
      Payment confirmed — thank you for your payment to CanaLogistiX.
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
                           alt="CanaLogistiX"
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
                        Thank you for your continued partnership with CanaLogistiX.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                    text = (
                        "Payment Confirmation - CanaLogistiX\n\n"
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




@csrf_exempt  # Making this consistent with other views
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


def _is_period_complete(end_date: date):
    """Check if the invoice period has ended (past 11:59 PM on end_date)."""
    # Get current time in user's timezone
    now = timezone.now().astimezone(USER_TZ)
    
    # Create datetime for 11:59:59 PM on the end date
    end_datetime = USER_TZ.localize(
        datetime.combine(end_date, datetime.max.time())
    )
    
    # Return True only if current time is past the end of period
    return now > end_datetime


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
    }


def _get_gcp_client():
    """Initialize and return GCP Storage client with service account key."""
    try:
        # Check if the key file exists
        if not os.path.exists(GCP_KEY_PATH):
            return None
        
        # Initialize client with service account key
        client = storage.Client.from_service_account_json(GCP_KEY_PATH)
        return client
    except Exception as e:
        return None


def _upload_to_gcp(pdf_buffer, filename):
    """Upload PDF to GCP Storage and return the public URL."""
    try:
        client = _get_gcp_client()
        if not client:
            return None
            
        bucket = client.bucket(GCP_BUCKET_NAME)
        blob_name = f"{GCP_FOLDER_NAME}/{filename}"
        blob = bucket.blob(blob_name)
        
        pdf_buffer.seek(0)
        blob.upload_from_file(pdf_buffer, content_type='application/pdf')
        
        # For uniform bucket-level access, construct the public URL directly
        public_url = f"https://storage.googleapis.com/{GCP_BUCKET_NAME}/{blob_name}"
        
        return public_url
    except Exception as e:
        return None




def _generate_invoice_pdf(driver, week_data, orders):
    """Generate comprehensive PDF invoice for a driver's weekly summary with modern design."""
    from io import BytesIO
    from decimal import Decimal
    from datetime import datetime
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.pdfgen import canvas
    from django.conf import settings
    from django.utils import timezone
    import os
    
    buffer = BytesIO()
    
    # Create PDF with professional margins
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4, 
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
    ACCENT_TEAL = colors.HexColor('#06B6D4')       # Accent teal
    
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
    
    # Small text
    small_text_style = ParagraphStyle(
        'SmallText',
        parent=styles['Normal'],
        fontSize=8,
        textColor=TEXT_GRAY,
        fontName='Helvetica',
        leading=11
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
    
    current_date = datetime.now().strftime("%B %d, %Y")
    invoice_number = f"INV-{driver.id}-{week_data['payment_period']['start_date'].replace('-', '')}"
    
    # Logo and company info side by side
    try:
        logo_path = settings.LOGO_PATH
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=2.2*inch, height=1.6*inch)
        else:
            raise FileNotFoundError
    except:
        # Create text-based logo if image not found
        logo_text = Paragraph(
            '<b><font size="20" color="#3B82F6">Cana</font><font size="20" color="#0F172A">LogistiX</font></b>',
            ParagraphStyle('LogoText', parent=styles['Normal'], alignment=TA_LEFT)
        )
        logo = logo_text
    
    company_info_text = f'''
    <b><font color="#0F172A" size="11">CanaLogistiX Delivery Services</font></b><br/>
    <font color="#64748B" size="9">Cana Group of Companies<br/>
    Operating Name of CANABELLE INC.<br/>
    BN: 758568562<br/>
    help.canalogistix@gmail.com<br/>
    Ontario, Canada</font>
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
    story.append(Paragraph("PAYMENT INVOICE", invoice_title_style))
    story.append(Paragraph(f"Driver Payment Summary for Week Ending {week_data['payment_period']['end_date']}", invoice_subtitle_style))
    
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
    
    # Driver information card
    driver_card_text = f'''
    <font color="#64748B" size="8"><b>DRIVER INFORMATION</b></font><br/>
    <font color="#0F172A" size="11"><b>{driver.name}</b></font><br/>
    <font color="#64748B" size="9">{driver.email}<br/>
    Driver ID: #{driver.id}<br/>
    Status: <font color="#10B981"><b>Active</b></font></font>
    '''
    
    # Payment period card
    start_date = week_data['payment_period']['start_date']
    end_date = week_data['payment_period']['end_date']
    
    period_card_text = f'''
    <font color="#64748B" size="8"><b>PAYMENT PERIOD</b></font><br/>
    <font color="#0F172A" size="11"><b>{start_date} to {end_date}</b></font><br/>
    <font color="#64748B" size="9">Payment Due: {week_data['due_date']}<br/>
    Status: {week_data['status'].title()}<br/>
    Total Orders: {week_data['total_orders']}</font>
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
    
    # ==================== FINANCIAL SUMMARY ====================
    
    story.append(Paragraph("Payment Breakdown", section_header_style))
    
    # Calculate financial details - MUST be done before any string formatting
    gross_amount = sum(Decimal(str(order.rate or 0)) for order in orders)
    commission_rate = Decimal(str(settings.DRIVER_COMMISSION_RATE))
    commission_percentage = int(commission_rate * 100)  # Calculate BEFORE using in strings
    commission_amount = gross_amount * commission_rate
    net_amount = gross_amount - commission_amount
    
    # Summary table with modern styling
    summary_data = [
        ['', ''],
        ['Total Deliveries Completed', f"{week_data['total_orders']} orders"],
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
    
    # ==================== ORDER DETAILS ====================
    
    if orders:
        story.append(Paragraph("Order Details", section_header_style))
        story.append(Spacer(1, 10))
        
        # Create order table
        order_data = [
            ['Order ID', 'Date', 'Pickup', 'Delivery', 'Status', 'Rate']
        ]
        
        for order in orders:
            delivery_date = order.updated_at.strftime('%m/%d/%Y') if order.updated_at else 'N/A'
            pickup_location = order.pickup_city if order.pickup_city else 'N/A'
            delivery_location = getattr(order, 'drop_city', None) or getattr(order, 'dropoff_city', None) or 'N/A'
            
            order_data.append([
                f"#{order.id}",
                delivery_date,
                pickup_location[:20],  # Truncate if too long
                delivery_location[:20],
                order.status.title(),
                f"${order.rate or 0:.2f}"
            ])
        
        order_table = Table(order_data, colWidths=[0.8*inch, 0.95*inch, 1.6*inch, 1.6*inch, 1*inch, 0.85*inch])
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
    
    # ==================== TERMS & CONDITIONS ====================
    
    story.append(Paragraph("Payment Terms & Conditions", section_header_style))
    
    terms_text = f'''
    <b>Payment Schedule:</b> Weekly payments are processed every Monday for completed deliveries from the previous week (Monday to Sunday).<br/><br/>
    
    <b>Commission Structure:</b> CanaLogistiX retains {commission_percentage}% of gross delivery fees to cover platform operations, insurance coverage, customer support services, and technology infrastructure.<br/><br/>
    
    <b>Payment Method:</b> Funds are transferred via direct deposit to your registered bank account within 2-3 business days of processing.<br/><br/>
    
    <b>Dispute Resolution:</b> Payment disputes must be submitted within 7 calendar days of invoice receipt. Contact our support team for assistance.<br/><br/>
    
    <b>Independent Contractor Status:</b> As an independent contractor, you are responsible for all applicable taxes, licenses, and insurance. This payment constitutes gross income for tax purposes.
    '''
    
    story.append(Paragraph(terms_text, body_style))
    story.append(Spacer(1, 30))
    
    # ==================== SUPPORT INFORMATION ====================
    
    story.append(Paragraph("Questions or Concerns?", section_header_style))
    
    support_text = '''
    Our support team is here to help with any questions about this invoice or your deliveries. Log in to the portal and raise a Support Ticket by contacting the Admin.<br/><br/>
    <b>Email:</b> help.canalogistix@gmail.com<br/>
    <b>Support Hours:</b> Monday - Friday, 9:00 AM - 6:00 PM EST<br/>
    <b>Response Time:</b> Within 24 business hours
    '''
    
    story.append(Paragraph(support_text, body_style))
    story.append(Spacer(1, 40))
    
    # ==================== FOOTER ====================
    
    footer_text = f'''
    <i>This invoice was automatically generated by CanaLogistiX payment processing system on {current_date}.<br/>
    Invoice Reference: {invoice_number} | Confidential Financial Document<br/>
    © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.</i>
    '''
    
    story.append(Paragraph(footer_text, footer_style))
    
    # Build PDF
    doc.build(story)
    
    return buffer


@csrf_exempt
def driver_invoice_weeks(request):
    """
    GET param: driverId
    Returns weekly invoice buckets for delivered orders for that driver.
    Generates PDF and uploads to GCP only after period ends (11:59 PM on end_date).
    """
    driver_id = request.GET.get("driverId") or request.POST.get("driverId")
    if not driver_id:
        return HttpResponseBadRequest('Missing "driverId" parameter.')

    # Validate driver exists
    try:
        driver = Driver.objects.get(pk=driver_id)
    except Driver.DoesNotExist:
        return HttpResponseBadRequest("Driver not found.")

    # Fetch delivered orders for this driver
    orders_qs = DeliveryOrder.objects.filter(status="delivered", driver_id=driver_id).order_by("updated_at")

    if not orders_qs.exists():
        return JsonResponse({"message": "No delivered orders found for this driver.", "weeks": []})

    # Convert updated_at to user's local tz and collect (order, local_date)
    orders_with_local_dt = []
    for o in orders_qs:
        if not o.updated_at:
            continue
        local_dt = _ensure_local(o.updated_at)
        orders_with_local_dt.append((o, local_dt))

    if not orders_with_local_dt:
        return JsonResponse({"message": "No orders with updated_at timestamps.", "weeks": []})

    # Determine overall earliest and latest based on local updated_at
    local_datetimes = [ldt for (_, ldt) in orders_with_local_dt]
    earliest_local = min(local_datetimes)
    latest_local = max(local_datetimes)

    overall_start_date = _start_of_week(earliest_local.date())
    overall_end_date = _end_of_week(latest_local.date())

    # Build week buckets
    weeks = []
    cur_start = overall_start_date
    while cur_start <= overall_end_date:
        cur_end = cur_start + timedelta(days=6)
        weeks.append((cur_start, cur_end))
        cur_start = cur_start + timedelta(days=7)

    # Prepare result weeks
    result_weeks = []
    for wstart, wend in weeks:
        # Select orders whose local updated_at date falls inside this week
        week_orders = [
            o for (o, ldt) in orders_with_local_dt
            if (ldt.date() >= wstart and ldt.date() <= wend)
        ]

        if not week_orders:  # Skip weeks with no orders
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

        # Check if DriverInvoice already exists for this period
        existing_invoice = DriverInvoice.objects.filter(
            driver=driver,
            start_date=wstart,
            end_date=wend
        ).first()

        pdf_url = None
        invoice_status = "pending"
        invoice_created = False

        # Only generate invoice if period is complete (after 11:59 PM on end date)
        if _is_period_complete(wend):
            if existing_invoice:
                # Use existing PDF URL if available
                pdf_url = existing_invoice.pdf_url
                invoice_status = "generated" if pdf_url else "pending"
            else:
                # Create new DriverInvoice and generate PDF
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

                # Generate PDF
                week_data = {
                    "payment_period": {
                        "start_date": wstart.isoformat(),
                        "end_date": wend.isoformat()
                    },
                    "total_orders": total_orders,
                    "total_amount": str(total_amount.quantize(Decimal("0.01"))),
                    "due_date": due_date.isoformat(),
                    "status": "generated",
                }

                try:
                    pdf_buffer = _generate_invoice_pdf(driver, week_data, week_orders)
                    
                    # Create filename: driverId_driverName_StartDate_EndDate.pdf
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{driver.id}_{driver.name.replace(' ', '_')}_{wstart.isoformat()}_{wend.isoformat()}_{timestamp}.pdf"
                    
                    # Upload to GCP
                    pdf_url = _upload_to_gcp(pdf_buffer, filename)
                    
                    if pdf_url:
                        new_invoice.pdf_url = pdf_url
                        new_invoice.save()
                        invoice_status = "generated"
                    else:
                        invoice_status = "error"
                        
                except Exception as e:
                    invoice_status = "error"

                # Send invoice notification email to delivery partner
                if invoice_created and pdf_url and driver.email:
                    try:
                        brand_primary = settings.BRAND_COLORS['primary']
                        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                        brand_accent = settings.BRAND_COLORS['accent']
                        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
                        logo_url = settings.LOGO_URL
                        
                        start_date_formatted = wstart.strftime("%B %d, %Y")
                        end_date_formatted = wend.strftime("%B %d, %Y")
                        due_date_formatted = due_date.strftime("%B %d, %Y")
                        total_amount_formatted = total_amount.quantize(Decimal("0.01"))
                        payment_rate_percent = settings.PAYMENT_RATE_PERCENT

                        # Using .format() to avoid f-string CSS brace conflicts
                        driver_invoice_html = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Payment Statement Available • CanaLogistiX</title>
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
                      <img src="{logo_url}" alt="CanaLogistiX" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
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
                        Thank you for being a valued Delivery Partner with CanaLogistiX!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {current_year} CanaLogistiX - Cana Group of Companies. All rights reserved.
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
                            start_date_formatted=start_date_formatted,
                            end_date_formatted=end_date_formatted,
                            total_amount=total_amount_formatted,
                            due_date_formatted=due_date_formatted,
                            total_orders=total_orders,
                            pdf_url=pdf_url,
                            now_str=now_str,
                            current_year=timezone.now().year,
                            payment_rate_percent=payment_rate_percent
                        )

                        driver_invoice_text = (
                            f"Payment Statement Available - CanaLogistiX\n\n"
                            f"Hello {driver.name},\n\n"
                            f"Your payment statement for the week of {start_date_formatted} to {end_date_formatted} is now available.\n\n"
                            f"PAYMENT SUMMARY:\n"
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
                            subject=f"Payment Statement Available • Week of {start_date_formatted}",
                            to_email=driver.email,
                            html=driver_invoice_html,
                            text_fallback=driver_invoice_text,
                        )
                        logger.info(f"Driver payment statement email sent to {driver.email} for week {wstart} to {wend}")
                        
                    except Exception as e:
                        logger.error(f"ERROR sending driver invoice email to {driver.email}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        # Don't fail the invoice generation if email fails

        # Serialize orders
        orders_serialized = [_order_to_dict(o) for o in week_orders]

        result_weeks.append({
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
        })

    response_payload = {
        "driver_id": int(driver_id),
        "overall_period": {
            "start_date": overall_start_date.isoformat(),
            "end_date": overall_end_date.isoformat()
        },
        "weeks": result_weeks,
    }

    return JsonResponse(response_payload, safe=True)


@csrf_exempt
@require_http_methods(["POST"])
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
        pharmacy_id = data.get('pharmacy_id')
        driver_id = data.get('driver_id')
        
        # Validate required fields
        if not subject:
            return JsonResponse({'error': 'Subject is required'}, status=400)
        
        if not message:
            return JsonResponse({'error': 'Message is required'}, status=400)
        
        # Validate that either pharmacy_id or driver_id is provided
        if not pharmacy_id and not driver_id:
            return JsonResponse({'error': 'User authentication required'}, status=400)
        
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
        
        # Prepare contact data
        contact_data = {
            'subject': subject,
            'message': message.strip(),
            'status': 'pending'
        }
        
        if subject == 'other':
            contact_data['other_subject'] = other_subject.strip()
        
        # Variables for email sending
        user_email = None
        user_name = None
        user_type = None
        user_id = None
        user_phone = None
        
        # Add pharmacy or driver reference
        if pharmacy_id:
            try:
                pharmacy = Pharmacy.objects.get(id=pharmacy_id)
                contact_data['pharmacy'] = pharmacy
                user_email = pharmacy.email
                user_name = pharmacy.name
                user_type = "Pharmacy"
                user_id = pharmacy.id
                user_phone = pharmacy.phone_number
            except Pharmacy.DoesNotExist:
                return JsonResponse({'error': 'Invalid pharmacy ID'}, status=400)
        
        if driver_id:
            try:
                driver = Driver.objects.get(id=driver_id)
                contact_data['driver'] = driver
                user_email = driver.email
                user_name = driver.name
                user_type = "Driver"
                user_id = driver.id
                user_phone = driver.phone_number
            except Driver.DoesNotExist:
                return JsonResponse({'error': 'Invalid driver ID'}, status=400)
        
        # Create record
        contact = ContactAdmin.objects.create(**contact_data)
        
        # ---- Send confirmation email ----
        if user_email:
            try:
                brand_primary = settings.BRAND_COLORS['primary']
                brand_primary_dark = settings.BRAND_COLORS['primary_dark']
                brand_accent = settings.BRAND_COLORS['accent']
                now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
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
    <title>Support Query Received • CanaLogistiX</title>
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
                        alt="CanaLogistiX"
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
                  Thank you for reaching out to <strong>CanaLogistiX</strong>. Your support query has been successfully 
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
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
                text = (
                    "Support Query Received - CanaLogistiX\n\n"
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
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
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
    <title>New Support Ticket • CanaLogistiX</title>
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
                           alt="CanaLogistiX"
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
                  A <strong>{user_type}</strong> has raised a support ticket on the CanaLogistiX platform.
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
                  This is an automated notification from the CanaLogistiX support system. Please review and respond to this ticket at your earliest convenience.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            office_text = (
                "New Support Ticket on CanaLogistiX\n\n"
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
        return JsonResponse({
            'error': 'An error occurred while processing your request. Please try again.'
        }, status=500)



OTP_TTL_SECONDS = settings.OTP_TTL_SECONDS
VERIFY_TOKEN_TTL_SECONDS = settings.VERIFY_TOKEN_TTL_SECONDS
SIGNING_SALT = settings.OTP_SIGNING_SALT

# ---- tiny helpers ----
def _json(request: HttpRequest):
    try:
        return json.loads(request.body.decode("utf-8"))
    except Exception:
        return {}

def _ok(message, **extra):  return JsonResponse({"success": True, "message": message, **extra})
def _err(message, code=400): return JsonResponse({"success": False, "message": message}, status=code)
def _otp_key(email: str) -> str: return f"otp:{email.strip().lower()}"

def _valid_email(addr: str) -> bool:
    try:
        validate_email(addr)
        return True
    except ValidationError:
        return False

# def _send_html_email(subject: str, to_email: str, html: str, text_fallback: str = " "):
#     msg = EmailMessage(subject=subject, body=html, from_email=EMAIL_FROM, to=[to_email])
#     msg.content_subtype = "html"
#     msg.send(fail_silently=False)




@csrf_exempt
def send_otp(request: HttpRequest):
    if request.method != "POST":
        return _err("Method not allowed", 405)

    data = _json(request)
    email = (data.get("email") or "").strip().lower()

    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")

    # Generate + store OTP in cache (plaintext for simplicity)
    otp = "".join(random.choice("0123456789") for _ in range(6))
    cache.set(_otp_key(email), otp, timeout=OTP_TTL_SECONDS)

    # --- Brand colors (bluish-green family used across the app) ---
    brand_primary = settings.BRAND_COLORS['primary']      
    brand_primary_dark = settings.BRAND_COLORS['primary_dark']
    brand_accent = settings.BRAND_COLORS['accent']

    # Modern, responsive-friendly HTML (works in Gmail/Outlook/Apple Mail)
    html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>CanaLogistiX Verification Code</title>
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
      Your CanaLogistiX verification code. Expires in {OTP_TTL_SECONDS//60} minute(s).
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
                            alt="CanaLogistiX"
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
                  Your CanaLogistiX verification code
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
            © {datetime.utcnow().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    subject = f"Your CanaLogistiX code • Expires in {OTP_TTL_SECONDS // 60} min"
    text = f"Your CanaLogistiX verification code is: {otp}\nThis code expires in {OTP_TTL_SECONDS//60} minute(s).\nIf you didn’t request it, you can ignore this message."

    try:
        _send_html_email_help_desk(subject, email, html, text)
    except Exception:
        # Swallow send errors but keep response generic (avoid account existence leak)
        pass

    return _ok("If a pharmacy exists for this email, an OTP will be sent shortly.")


@csrf_exempt
def verify_otp(request: HttpRequest):
    if request.method != "POST":
        return _err("Method not allowed", 405)

    data = _json(request)
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")
    if not otp.isdigit() or not (4 <= len(otp) <= 8):
        return _err("Please provide a valid OTP.")

    stored = cache.get(_otp_key(email))
    if not stored:
        return _err("OTP expired or not found. Please request a new one.", 400)

    if stored != otp:
        return _err("Incorrect OTP.", 400)

    # success: clear OTP and mint a short-lived token tied to the email
    cache.delete(_otp_key(email))
    token = dumps({"email": email}, salt=SIGNING_SALT)  # signed with SECRET_KEY

    return _ok("OTP verified.", token=token, expires_in=VERIFY_TOKEN_TTL_SECONDS)



@csrf_exempt
def change_password(request: HttpRequest):
    if request.method != "POST":
        return _err("Method not allowed", 405)

    data = _json(request)
    email = (data.get("email") or "").strip().lower()
    new_password = (data.get("newPassword") or "").strip()
    confirm_password = (data.get("confirmPassword") or "").strip()
    token = (data.get("otpToken") or "").strip()

    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")
    if not token:
        return _err("Missing verification token.")
    if not new_password or not confirm_password:
        return _err("Please provide both password fields.")
    if new_password != confirm_password:
        return _err("New Password and Confirm Password must match.")
    if len(new_password) < 8:
        return _err("Password must be at least 8 characters long.")

    # validate token + email match
    try:
        data = loads(token, salt=SIGNING_SALT, max_age=VERIFY_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        return _err("Verification token is invalid or expired.", 400)
    except BadSignature:
        return _err("Verification token is invalid or expired.", 400)

    if data.get("email") != email:
        return _err("Verification token does not match this email.", 400)

    # update Pharmacy password (must exist here; if not, return generic 404)
    try:
        pharmacy = Pharmacy.objects.get(email__iexact=email)
    except Pharmacy.DoesNotExist:
        return _err("No pharmacy account found with this email.", 404)

    pharmacy.password = make_password(new_password)
    pharmacy.save(update_fields=["password"])

    try:
        # Brand colors (bluish green family)
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']

        logo_url = settings.LOGO_URL
        changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")
        site_url = settings.SITE_URL.rstrip("/")
        reset_link = f"{site_url}/forgotPassword/" if site_url else "/forgotPassword/"

        html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed Successfully • CanaLogistiX</title>
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
    <!-- Preheader (hidden) -->
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your CanaLogistiX password was changed on {changed_at}.
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
                        <img src="{logo_url}"
                            alt="CanaLogistiX"
                            width="64" height="64"
                            style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                        </td>
                        <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                        Security Notification
                        </td>
                    </tr>
                    </table>
                </td>
                </tr>


            <!-- Content -->
            <tr>
              <td style="padding:28px 24px 10px 24px;">
                <h1 style="margin:0 0 10px 0;font:700 22px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Password Changed Successfully
                </h1>
                <p style="margin:0 0 16px 0;font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Your CanaLogistiX account password was changed on
                  <strong style="color:{brand_primary_dark}">{changed_at}</strong>.
                </p>

                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;" class="panel">
                  <tr>
                    <td style="padding:14px 16px;">
                      <p style="margin:0 0 6px 0;font:400 13px/1.65 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        If <strong>you</strong> made this change, no further action is needed.
                      </p>
                      <p style="margin:0;font:400 13px/1.65 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                        If this wasn’t you, please reset your password immediately
                        
                      </p>
                    </td>
                  </tr>
                </table>

                <p class="muted" style="margin:16px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  For your security, never share your password with anyone.
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:0 24px 24px 24px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f8fafc;border:1px dashed #e2e8f0;border-radius:12px;" class="panel">
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
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "CanaLogistiX — Password Changed Successfully\n\n"
            f"Timestamp: {changed_at}\n\n"
            "If you did not make this change, please reset your password immediately:\n"
            f"{reset_link}\n"
        )

        _send_html_email_help_desk(
            subject="Your CanaLogistiX password was changed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        # Keep API response the same; just log email errors for visibility
        logger.exception("Password-change email failed to send")

    return _ok("Password changed successfully.")




@csrf_exempt
def change_password_driver(request: HttpRequest):
    if request.method != "POST":
        return _err("Method not allowed", 405)

    data = _json(request)
    email = (data.get("email") or "").strip().lower()
    new_password = (data.get("newPassword") or "").strip()
    confirm_password = (data.get("confirmPassword") or "").strip()
    token = (data.get("otpToken") or "").strip()

    if not email or not _valid_email(email):
        return _err("Please provide a valid email address.")
    if not token:
        return _err("Missing verification token.")
    if not new_password or not confirm_password:
        return _err("Please provide both password fields.")
    if new_password != confirm_password:
        return _err("New Password and Confirm Password must match.")
    if len(new_password) < 8:
        return _err("Password must be at least 8 characters long.")

    try:
        token_data = loads(token, salt=SIGNING_SALT, max_age=VERIFY_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        return _err("Verification token is invalid or expired.", 400)
    except BadSignature:
        return _err("Verification token is invalid or expired.", 400)

    if token_data.get("email") != email:
        return _err("Verification token does not match this email.", 400)

    # Update DRIVER password
    try:
        driver = Driver.objects.get(email__iexact=email)
    except Driver.DoesNotExist:
        return _err("No driver account found with this email.", 404)

    driver.password = make_password(new_password)
    driver.save(update_fields=["password"])

    # ---- Dark theme email (bluish grey + teal accent) ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        bg_dark = settings.BRAND_COLORS['bg_dark']
        card_dark = settings.BRAND_COLORS['card_dark']
        border_dark = settings.BRAND_COLORS['border_dark']
        text_light = settings.BRAND_COLORS['text_light']
        text_muted = settings.BRAND_COLORS['text_muted']

        logo_url = settings.LOGO_URL
        changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")

        html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed • CanaLogistiX Driver</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background:{bg_dark};">
    <!-- Preheader (hidden) -->
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your CanaLogistiX driver password was changed on {changed_at}.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};padding:24px 12px;">
      <tr>
        <td align="center">
          <!-- Card -->
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:{card_dark};border:1px solid {border_dark};border-radius:16px;overflow:hidden;">
            <!-- Header bar -->
            <tr>
            <td style="background:{brand_primary};padding:18px 20px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td align="left" style="vertical-align:middle;">
                    <img src="{logo_url}"
                        alt="CanaLogistiX"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Security Notification
                    </td>
                </tr>
                </table>
            </td>
            </tr>


            <!-- Content -->
            <tr>
              <td style="padding:28px 24px 10px 24px;">
                <h1 style="margin:0 0 10px 0;font:700 22px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
                  Password Changed Successfully
                </h1>
                <p style="margin:0 0 16px 0;font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Your CanaLogistiX <strong style="color:{text_light};">driver</strong> account password was changed on
                  <strong style="color:{brand_primary};">{changed_at}</strong>.
                </p>

                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;">
                  <tr>
                    <td style="padding:14px 16px;">
                      <p style="margin:0 0 6px 0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
                        If <strong>you</strong> made this change, no further action is needed.
                      </p>
                      <p style="margin:0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                        If this wasn’t you, please reset your password immediately.
                      </p>
                    </td>
                  </tr>
                </table>

                <p style="margin:16px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  For your security, never share your password with anyone.
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:0 24px 24px 24px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;">
                  <tr>
                    <td style="padding:12px 16px;">
                      <p style="margin:0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                        Need help? Reply to this email and our team will assist you.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <!-- Brand footer -->
          <p style="margin:14px 0 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "CanaLogistiX — Driver Password Changed Successfully\n\n"
            f"Timestamp: {changed_at}\n\n"
            "If you did not make this change, please reset your password immediately."
        )

        _send_html_email_help_desk(
            subject="Your CanaLogistiX driver password was changed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Driver password-change email failed to send")

    return _ok("Driver password changed successfully.")





@csrf_exempt
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
    """
    if request.method != "POST":
        return _err("Method not allowed", 405)

    data = _json(request)

    # Extract
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

    # Basic validations
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

    if len(password) < 8:
        return _err("Password must be at least 8 characters long.")

    # Verify OTP token and email match
    try:
        token_data = loads(otp_token, salt=SIGNING_SALT, max_age=VERIFY_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        return _err("Verification token is invalid or expired.", 400)
    except BadSignature:
        return _err("Verification token is invalid or expired.", 400)

    token_email = (token_data.get("email") or "").strip().lower()
    if token_email != email:
        return _err("Verification token does not match this email.", 400)

    # Create pharmacy
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
                password=password,  # hashed by Pharmacy.save()
            )
    except IntegrityError:
        return _err("An account with this email already exists.", 409)

    # ---- Light-theme welcome email (Pharmacy) ----
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
    <title>Welcome to CanaLogistiX • Pharmacy Registration</title>
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
      Registration confirmed — welcome to CanaLogistiX and the Cana Family by CGC.
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
                        alt="CanaLogistiX"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Welcome to CanaLogistiX
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
                  Thanks for registering with <strong>CanaLogistiX</strong> and joining the <strong>Cana Family by CGC</strong>.
                  We’re excited to help your team coordinate secure, trackable, and timely deliveries with a dashboard
                  designed for pharmacies.
                </p>

                <div style="margin:18px 0;background:#f0fdfa;border:1px solid {brand_primary};border-radius:12px;padding:16px 18px;">
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    <li>Live order tracking with photo proof at each stage</li>
                    <li>Smart weekly invoices and transparent earnings</li>
                    <li>Secure driver handover and delivery confirmations</li>
                  </ul>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">
                  Registered on <strong style="color:{brand_primary_dark};">{now_str}</strong>.
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
                        Welcome aboard — we’re thrilled to partner with you.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "Welcome to CanaLogistiX and the Cana Family by CGC!\n\n"
            f"Hi {name or 'there'}, your pharmacy registration is confirmed.\n"
            "• Live order tracking with photo proof\n"
            "• Weekly invoices and transparent earnings\n"
            "• Secure handover and delivery confirmations\n\n"
            "Questions? Just reply to this email.\n"
        )

        _send_html_email_help_desk(
            subject="Welcome to CanaLogistiX • Pharmacy Registration Confirmed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send pharmacy registration email")
    
    # ---- Office notification email (New Pharmacy Registration) ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
        logo_url = settings.LOGO_URL

        office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Pharmacy Registration • CanaLogistiX</title>
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
                           alt="CanaLogistiX"
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
                  A new pharmacy has successfully registered on the CanaLogistiX platform.
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
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
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
                  This is an automated notification from the CanaLogistiX registration system.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        office_text = (
            "New Pharmacy Registration on CanaLogistiX\n\n"
            f"Pharmacy Name: {name}\n"
            f"Email: {email}\n"
            f"Phone: {phone_number}\n"
            f"Address: {store_address}\n"
            f"City: {city}\n"
            f"Province: {province}\n"
            f"Postal Code: {postal_code}\n"
            f"Country: {country}\n"
            f"Registration Time: {now_str}\n"
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

    return _ok("Registration successful.", id=pharmacy.id, email=pharmacy.email)




@csrf_exempt
def register_driver(request: HttpRequest):
    """
    POST /api/driver/register/
    {
      "name": "John Doe",
      "phone_number": "416-555-1212",
      "email": "driver@example.com",
      "password": "StrongPass#1",
      "vehicle_number": "ABC-1234",      # REQUIRED
      "otpToken": "<token from /api/auth/verify-otp/>"
    }
    """
    if request.method != "POST":
        return _err("Method not allowed", 405)

    data = _json(request)

    name           = (data.get("name") or "").strip()
    phone_number   = (data.get("phone_number") or "").strip()
    email          = (data.get("email") or "").strip().lower()
    password       = (data.get("password") or "").strip()
    vehicle_number = (data.get("vehicle_number") or "").strip()  # REQUIRED
    otp_token      = (data.get("otpToken") or "").strip()

    # Required fields (vehicle_number included)
    required = {
        "name": name,
        "phone_number": phone_number,
        "email": email,
        "password": password,
        "vehicle_number": vehicle_number,
        "otpToken": otp_token,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        return _err("Missing required fields.", 400, missing=missing)

    if not _valid_email(email):
        return _err("Please provide a valid email address.")
    if len(password) < 8:
        return _err("Password must be at least 8 characters long.")

    # Validate OTP token matches email
    try:
        token_data = loads(otp_token, salt=SIGNING_SALT, max_age=VERIFY_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        return _err("Verification token is invalid or expired.", 400)
    except BadSignature:
        return _err("Verification token is invalid or expired.", 400)

    if (token_data.get("email") or "").strip().lower() != email:
        return _err("Verification token does not match this email.", 400)

    # Create Driver
    try:
        with transaction.atomic():
            driver = Driver.objects.create(
                name=name,
                phone_number=phone_number,
                email=email,
                password=password,        # hashed by Driver.save()
                vehicle_number=vehicle_number,
            )
    except IntegrityError:
        return _err("An account with this email already exists.", 409)

    # ---- Dark-theme welcome email (Driver) ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        bg_dark = settings.BRAND_COLORS['bg_dark']
        card_dark = settings.BRAND_COLORS['card_dark']
        border_dark = settings.BRAND_COLORS['border_dark']
        text_light = settings.BRAND_COLORS['text_light']
        text_muted = settings.BRAND_COLORS['text_muted']
        logo_url = settings.LOGO_URL
        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")

        html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to CanaLogistiX • Driver Registration</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background:{bg_dark};">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Registration confirmed — welcome to CanaLogistiX and the Cana Family by CGC.
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
                        alt="CanaLogistiX"
                        width="64"
                        height="64"
                        style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                    Welcome to CanaLogistiX
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
                  Welcome to <strong style="color:{text_light};">CanaLogistiX</strong> and the <strong style="color:{text_light};">Cana Family by CGC</strong>.
                  You now have access to a streamlined delivery experience with clear routes, photo-verified steps, and
                  weekly earnings summaries.
                </p>

                <div style="margin:18px 0;background:{bg_dark};border:1px dashed {border_dark};border-radius:12px;padding:16px 18px;">
                  <ul style="margin:0;padding-left:18px;font:400 14px/1.8 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
                    <li>Pickup → in-transit → delivered — all verified with photos</li>
                    <li>Clear delivery details and navigation shortcuts</li>
                    <li>Automatic weekly payouts with transparent summaries</li>
                  </ul>
                </div>

                <p style="margin:8px 0 0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Registered on <strong style="color:{text_light};">{now_str}</strong>.
                </p>

                <hr style="border:0;border-top:1px solid {border_dark};margin:24px 0;">
                <p style="margin:0;font:400 12px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Drive safe and welcome aboard. Need help? Reply to this email and our team will assist you.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "Welcome to CanaLogistiX and the Cana Family by CGC!\n\n"
            f"Hey {name or 'driver'}, your driver registration is confirmed.\n"
            "• Photo-verified delivery steps\n"
            "• Clear delivery details and navigation\n"
            "• Weekly earnings summaries\n\n"
            "Questions or need a hand? Log in to the portal and raise a Support Ticket by contacting the Admin. Our team will be happy to assist you.\n"
        )

        _send_html_email_help_desk(
            subject="Welcome to CanaLogistiX • Delivery Partner Registration Confirmed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send driver registration email")
    
    # ---- Office notification email (New Driver Registration) ----
    try:
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
        logo_url = settings.LOGO_URL

        office_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>New Delivery Partner Registration • CanaLogistiX</title>
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
                           alt="CanaLogistiX"
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
                  A new delivery partner has successfully registered on the CanaLogistiX platform.
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
                      <td style="padding:12px 18px;color:{brand_primary_dark};font-weight:500;border-top:1px solid #e2e8f0;">{now_str}</td>
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
                  This is an automated notification from the CanaLogistiX registration system.
                </p>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        office_text = (
            "New Driver Registration on CanaLogistiX\n\n"
            f"Driver Name: {name}\n"
            f"Email: {email}\n"
            f"Phone: {phone_number}\n"
            f"Vehicle Number: {vehicle_number}\n"
            f"Registration Time: {now_str}\n"
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

    return _ok("Driver registration successful.", id=driver.id, email=driver.email)




@csrf_exempt
@require_GET
def get_pharmacy_details(request, pharmacy_id):
    """
    GET API: Returns all information of a pharmacy by pharmacyId.
    Example: /api/getPharmacyDetails/1/
    """
    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)

        # ✅ Format business hours nicely
        days_order = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        day_full = {
            "Mon": "Monday", "Tue": "Tuesday", "Wed": "Wednesday",
            "Thu": "Thursday", "Fri": "Friday", "Sat": "Saturday", "Sun": "Sunday"
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
                # Keep as HH:MM; if you want AM/PM later, tell me
                formatted_lines.append(f"{day_full[d]}: {open_t} - {close_t}")

        data = {
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
                "created_at": pharmacy.created_at.strftime("%Y-%m-%d %H:%M:%S"),

                "business_hours_raw": business_hours,
                "business_hours_formatted": formatted_lines,  # array of strings
            },
        }
        return JsonResponse(data, status=200)

    except Pharmacy.DoesNotExist:
        return JsonResponse({"success": False, "error": "Pharmacy not found."}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)




@csrf_exempt
@require_POST
def change_existing_password(request):
    """
    POST API to change an existing pharmacy password.
    Request Body (JSON):
    {
        "pharmacyId": 1,
        "old_password": "current_pass",
        "new_password": "new_secure_pass"
    }
    """
    try:
        data = json.loads(request.body.decode("utf-8"))
        pharmacy_id = data.get("pharmacyId")
        old_password = data.get("old_password")
        new_password = data.get("new_password")

        if not (pharmacy_id and old_password and new_password):
            return JsonResponse({"success": False, "error": "Missing required fields."}, status=400)

        # Retrieve pharmacy
        try:
            pharmacy = Pharmacy.objects.get(id=pharmacy_id)
        except Pharmacy.DoesNotExist:
            return JsonResponse({"success": False, "error": "Pharmacy not found."}, status=404)

        # Verify old password
        if not pharmacy.check_password(old_password):
            return JsonResponse({"success": False, "error": "Incorrect old password."}, status=401)

        # Update new password
        pharmacy.password = make_password(new_password)
        pharmacy.save(update_fields=["password"])

        # Send confirmation email
        _send_password_change_email(pharmacy.email)

        return JsonResponse({"success": True, "message": "Password changed successfully."}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



def _send_password_change_email(email):
    """
    Sends a styled HTML + text password change confirmation email to the pharmacy.
    """
    brand_primary = settings.BRAND_COLORS['primary']
    brand_primary_dark = settings.BRAND_COLORS['primary_dark']
    logo_url = settings.LOGO_URL
    changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")

    html_content = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed Successfully • CanaLogistiX</title>
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
      Your CanaLogistiX password was changed on {changed_at}.
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
                        alt="CanaLogistiX"
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
                  Your CanaLogistiX account password was changed on
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
                        If this wasn’t you, please reset your password immediately from the login page.
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
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    text_content = (
        f"CanaLogistiX — Password Changed Successfully\n\n"
        f"Your password was changed on {changed_at}.\n\n"
        "If you did not perform this change, please reset your password immediately.\n\n"
        "CanaLogistiX Support\n"
    )

    subject = "Your CanaLogistiX Password Was Changed Successfully"
    from_email = settings.DEFAULT_FROM_EMAIL
    msg = EmailMultiAlternatives(subject, text_content, from_email, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send(fail_silently=True)





# @csrf_exempt
# @require_POST
# def edit_pharmacy_profile(request):
#     """
#     POST API to update pharmacy profile information.
#     It accepts pharmacyId and any combination of editable fields.
#     Example Body:
#     {
#         "pharmacyId": 1,
#         "name": "New Pharmacy Name",
#         "store_address": "123 New Street",
#         "city": "Waterloo",
#         "province": "Ontario",
#         "postal_code": "N2L 3E2",
#         "country": "Canada",
#         "phone_number": "9876543210",
#         "email": "newemail@pharmacy.com"
#     }
#     """
#     try:
#         data = json.loads(request.body.decode("utf-8"))
#         pharmacy_id = data.get("pharmacyId")

#         if not pharmacy_id:
#             return JsonResponse({"success": False, "error": "pharmacyId is required."}, status=400)

#         try:
#             pharmacy = Pharmacy.objects.get(id=pharmacy_id)
#         except Pharmacy.DoesNotExist:
#             return JsonResponse({"success": False, "error": "Pharmacy not found."}, status=404)

#         # Allowed editable fields
#         editable_fields = [
#             "name",
#             "store_address",
#             "city",
#             "province",
#             "postal_code",
#             "country",
#             "phone_number",
#             "email"
#         ]

#         # Track updated fields
#         updated_fields = []

#         for field in editable_fields:
#             if field in data and getattr(pharmacy, field) != data[field]:
#                 setattr(pharmacy, field, data[field])
#                 updated_fields.append(field)

#         if not updated_fields:
#             return JsonResponse({"success": False, "message": "No fields were changed."}, status=200)

#         # Save only changed fields
#         pharmacy.save(update_fields=updated_fields)

#         return JsonResponse({
#             "success": True,
#             "message": f"Profile updated successfully.",
#             "updated_fields": updated_fields
#         }, status=200)

#     except json.JSONDecodeError:
#         return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)
#     except Exception as e:
#         return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_POST
def edit_pharmacy_profile(request):
    """
    POST API to update pharmacy profile information (including business hours).
    """
    try:
        data = json.loads(request.body.decode("utf-8"))
        pharmacy_id = data.get("pharmacyId")

        if not pharmacy_id:
            return JsonResponse({"success": False, "error": "pharmacyId is required."}, status=400)

        try:
            pharmacy = Pharmacy.objects.get(id=pharmacy_id)
        except Pharmacy.DoesNotExist:
            return JsonResponse({"success": False, "error": "Pharmacy not found."}, status=404)

        # Editable scalar fields
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

        # Handle normal fields
        for field in editable_fields:
            if field in data and getattr(pharmacy, field) != data[field]:
                setattr(pharmacy, field, data[field])
                updated_fields.append(field)

        # ✅ Handle business hours separately
        if "business_hours" in data:
            incoming_hours = data["business_hours"]

            # Basic validation
            if not isinstance(incoming_hours, dict):
                return JsonResponse(
                    {"success": False, "error": "business_hours must be an object."},
                    status=400
                )

            valid_days = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

            for day, value in incoming_hours.items():
                if day not in valid_days:
                    return JsonResponse(
                        {"success": False, "error": f"Invalid day: {day}"},
                        status=400
                    )

                if value != "closed":
                    if (
                        not isinstance(value, dict)
                        or "open" not in value
                        or "close" not in value
                    ):
                        return JsonResponse(
                            {
                                "success": False,
                                "error": f"Invalid hours format for {day}"
                            },
                            status=400
                        )

            if pharmacy.business_hours != incoming_hours:
                pharmacy.business_hours = incoming_hours
                updated_fields.append("business_hours")

        if not updated_fields:
            return JsonResponse(
                {"success": False, "message": "No fields were changed."},
                status=200
            )

        pharmacy.save(update_fields=updated_fields)

        return JsonResponse({
            "success": True,
            "message": "Profile updated successfully.",
            "updated_fields": updated_fields
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)






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


@csrf_exempt
@require_http_methods(["POST"])
def optimize_route_api(request):
    """
    Optimized delivery route API with:
    - Parallel distance matrix fetching
    - Distance matrix caching
    - Adaptive solver timeouts
    - Better error handling
    - Consolidated consecutive same-address stops
    """
    try:
        data = json.loads(request.body)
        driver_start = data.get("driver_start")
        deliveries = data.get("deliveries", [])

        logger.info(f"Received optimization request: driver_start={driver_start}, deliveries={len(deliveries)}")

        if not driver_start or not deliveries:
            return JsonResponse({"error": "Missing required data", "success": False}, status=400)

        if not isinstance(deliveries, list) or len(deliveries) == 0:
            return JsonResponse({"error": "No deliveries provided", "success": False}, status=400)

        # Use secure Google Maps API key
        api_key = settings.GOOGLE_MAPS_API_KEY
        if not api_key:
            logger.error("Google Maps API key not configured")
            return JsonResponse({"error": "API key not configured", "success": False}, status=500)

        gmaps = googlemaps.Client(key=api_key)

        # Group deliveries by pickup date
        deliveries_by_date = defaultdict(list)
        from datetime import datetime, date
        today = date.today()
        
        for d in deliveries:
            if not d.get("pickup_address") or not d.get("dropoff_address"):
                logger.warning(f"Skipping delivery with missing address: {d}")
                continue
            
            # Extract date from pickup_date
            pickup_date = d.get("pickup_date", "unknown")
            if isinstance(pickup_date, str) and 'T' in pickup_date:
                pickup_date = pickup_date.split('T')[0]
            
            # Skip past dates
            try:
                delivery_date = datetime.strptime(pickup_date, '%Y-%m-%d').date()
                if delivery_date < today:
                    logger.info(f"Skipping past date delivery: {pickup_date} for order {d.get('order_id')}")
                    continue
            except:
                logger.warning(f"Invalid date format: {pickup_date}, including in optimization")
            
            deliveries_by_date[pickup_date].append(d)
        
        if len(deliveries_by_date) == 0:
            return JsonResponse({
                "error": "No current or future deliveries to optimize", 
                "success": False
            }, status=400)
        
        logger.info(f"Grouped {sum(len(v) for v in deliveries_by_date.values())} deliveries into {len(deliveries_by_date)} date groups")

        # Process each date group
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
                    "error": f"Failed to optimize route for {date_key}: {str(e)}", 
                    "success": False
                }, status=500)

        # Consolidate consecutive stops at same address
        consolidated_stops = consolidate_consecutive_stops(all_stops)

        logger.info(f"✓✓ FULL ROUTE OPTIMIZED: {len(consolidated_stops)} total stops (consolidated from {len(all_stops)}), {round(total_distance/1000, 2)}km across {len(deliveries_by_date)} dates")

        return JsonResponse({
            "success": True,
            "stops": consolidated_stops,
            "total_distance_km": round(total_distance / 1000, 2),
            "dates_optimized": len(deliveries_by_date)
        })

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return JsonResponse({"error": "Invalid JSON payload", "success": False}, status=400)
    except Exception as e:
        logger.exception(f"Unexpected error in route optimization: {str(e)}")
        return JsonResponse({"error": f"Internal server error: {str(e)}", "success": False}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def admin_login(request):
    try:
        # Parse JSON
        try:
            data = json.loads(request.body or b"{}")
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "message": "Invalid JSON format"},
                status=400,
            )

        email = (data.get("email") or "").strip()
        password = (data.get("password") or "").strip()

        # Basic validations
        if not email or not password:
            return JsonResponse(
                {"success": False, "message": "Email and password are required"},
                status=400,
            )

        # Fetch admin (case-insensitive email match)
        admin = AdminUser.objects.filter(email__iexact=email).first()
        if not admin:
            return JsonResponse(
                {"success": False, "message": "Invalid credentials"},
                status=401,
            )

        # Validate password (hashed or fallback to plain-text compare if ever stored that way)
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
                status=401,
            )

        # Success
        return JsonResponse(
            {
                "success": True,
                "id": admin.id,
                "message": "Login successful",
                # Optional convenience fields:
                "first_name": admin.first_name,
                "last_name": admin.last_name,
                "email": admin.email,
            },
            status=200,
        )

    except Exception:
        # Avoid leaking internals
        return JsonResponse(
            {"success": False, "message": "An error occurred during login"},
            status=500,
        )



@csrf_exempt
def admin_dashboard_stats(request):
    try:
        # 1️⃣ Total active pharmacies
        total_pharmacies = Pharmacy.objects.filter(active=True).count()

        # 2️⃣ Total active drivers
        total_drivers = Driver.objects.filter(active=True).count()

        # 3️⃣ Active orders: pending / accepted / inTransit / picked_up
        active_statuses = ['pending', 'accepted', 'inTransit', 'picked_up']
        active_orders = DeliveryOrder.objects.filter(status__in=active_statuses).count()

        # 4️⃣ Revenue this month (sum of rate for delivered)
        today = date.today()
        revenue_this_month = (
            DeliveryOrder.objects.filter(
                status='delivered',
                created_at__year=today.year,
                created_at__month=today.month
            ).aggregate(total=Sum('rate'))['total'] or 0
        )

        # 5️⃣ Driver payouts this month
        # include invoices where start_date OR end_date is in current month
        driver_payout_this_month = (
            DriverInvoice.objects.filter(
                Q(start_date__year=today.year, start_date__month=today.month)
                | Q(end_date__year=today.year, end_date__month=today.month)
            ).aggregate(total=Sum('total_amount'))['total'] or 0
        )

        data = {
            "success": True,
            "metrics": {
                "total_pharmacies": total_pharmacies,
                "total_drivers": total_drivers,
                "active_orders": active_orders,
                "revenue_this_month": float(revenue_this_month),
                "driver_payout_this_month": float(driver_payout_this_month),
            }
        }
        return JsonResponse(data, status=200)

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)





@csrf_exempt
def recent_activity_feed(request):
    """
    Returns a unified feed of the most recent 8 activity items across
    Orders, Invoices, Drivers, Pharmacies, and Support Tickets.
    Ensures a balanced mix from different tables.
    """
    try:
        # Helper to safely slice even when fewer items exist
        def safe_slice(qs, n): 
            return list(qs[:n])

        # 1️⃣ Recent Orders
        orders = safe_slice(
            DeliveryOrder.objects.select_related("pharmacy", "driver")
            .order_by("-created_at"), 3
        )
        order_feed = [{
            "type": "Order",
            "title": f"Order #{o.id} ({o.status})",
            "description": f"Placed by {o.pharmacy.name}. "
                           f"Driver: {o.driver.name if o.driver else 'Unassigned'}",
            "timestamp": o.created_at,
        } for o in orders]

        # 2️⃣ Recent Pharmacy Invoices
        invoices = safe_slice(
            Invoice.objects.select_related("pharmacy")
            .order_by("-created_at"), 2
        )
        invoice_feed = [{
            "type": "Pharmacy Invoice",
            "title": f"Invoice #{inv.id} ({inv.status})",
            "description": f"Generated for {inv.pharmacy.name} "
                           f"(${inv.total_amount}, {inv.total_orders} orders)",
            "timestamp": inv.created_at,
        } for inv in invoices]

        # 3️⃣ Recent Driver Invoices
        driver_invoices = safe_slice(
            DriverInvoice.objects.select_related("driver")
            .order_by("-created_at"), 1
        )
        driver_invoice_feed = [{
            "type": "Driver Invoice",
            "title": f"Driver Invoice #{d.id} ({d.status})",
            "description": f"For driver {d.driver.name}, total ${d.total_amount}",
            "timestamp": d.created_at,
        } for d in driver_invoices]

        # 4️⃣ Recently Registered Pharmacies
        pharmacies = safe_slice(
            Pharmacy.objects.order_by("-created_at"), 1
        )
        pharmacy_feed = [{
            "type": "New Pharmacy",
            "title": f"{p.name} joined CanaLogistiX",
            "description": f"Located in {p.city}, {p.province}",
            "timestamp": p.created_at,
        } for p in pharmacies]

        # 5️⃣ Recently Registered Drivers
        drivers = safe_slice(
            Driver.objects.order_by("-created_at"), 1
        )
        driver_feed = [{
            "type": "New Driver",
            "title": f"{d.name} registered as driver",
            "description": f"Vehicle #{d.vehicle_number or 'N/A'}",
            "timestamp": d.created_at,
        } for d in drivers]

        # 6️⃣ Recent Support Tickets
        tickets = safe_slice(
            ContactAdmin.objects.select_related("pharmacy", "driver")
            .order_by("-created_at"), 2
        )
        ticket_feed = [{
            "type": "Support Ticket",
            "title": f"{t.get_subject_display()} ({t.status})",
            "description": f"From {t.pharmacy.name if t.pharmacy else t.driver.name if t.driver else 'Unknown'}",
            "timestamp": t.created_at,
        } for t in tickets]

        # Combine all feeds
        combined = list(chain(
            order_feed, invoice_feed, driver_invoice_feed,
            pharmacy_feed, driver_feed, ticket_feed
        ))

        # Sort by timestamp (latest first)
        combined.sort(key=lambda x: x["timestamp"], reverse=True)

        # Take only the most recent 8 items overall
        recent_8 = combined[:8]

        # Convert datetime to ISO
        for item in recent_8:
            item["timestamp"] = item["timestamp"].isoformat()

        return JsonResponse({
            "success": True,
            "recent_activity": recent_8,
            "count": len(recent_8),
            "generated_at": now().isoformat()
        })

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)




@csrf_exempt
def order_tracking_overview(request):
    """
    Returns a detailed list of all delivery orders
    with their tracking history and proof images.
    """
    try:
        all_orders = DeliveryOrder.objects.select_related("pharmacy", "driver").order_by("-created_at")

        result = []
        for order in all_orders:
            # Fetch all tracking events for this order
            trackings = OrderTracking.objects.filter(order=order).select_related("driver", "pharmacy").order_by("timestamp")
            tracking_history = []
            for t in trackings:
                tracking_history.append({
                    "step": t.step,
                    "performed_by": t.performed_by or (t.driver.name if t.driver else t.pharmacy.name if t.pharmacy else "Unknown"),
                    "timestamp": t.timestamp.isoformat(),
                    "note": t.note or "",
                    "image_url": t.image_url or None
                })

            # Fetch proof images for this order
            proof_images = OrderImage.objects.filter(order=order).order_by("uploaded_at")
            images = [{
                "stage": img.stage,
                "image_url": img.image_url,
                "uploaded_at": img.uploaded_at.isoformat()
            } for img in proof_images]

            result.append({
                "order_id": order.id,
                "status": order.status,
                "rate": float(order.rate),
                "pickup_city": order.pickup_city,
                "drop_city": order.drop_city,
                "pickup_day": order.pickup_day.isoformat(),
                "customer_name": order.customer_name,
                "pharmacy": {
                    "id": order.pharmacy.id,
                    "name": order.pharmacy.name,
                    "city": order.pharmacy.city,
                    "email": order.pharmacy.email,
                },
                "driver": ({
                    "id": order.driver.id,
                    "name": order.driver.name,
                    "vehicle_number": order.driver.vehicle_number
                } if order.driver else None),
                "tracking_history": tracking_history,
                "proof_images": images,
                "created_at": order.created_at.isoformat(),
                "updated_at": order.updated_at.isoformat(),
            })

        return JsonResponse({
            "success": True,
            "orders": result,
            "count": len(result),
            "generated_at": now().isoformat()
        })

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



@csrf_exempt
def admin_alerts(request):
    """
    Incremental alert building with error isolation
    """
    alerts = {
        "operational": [],
        "financial": [],
        "support": []
    }
    
    errors = []
    current_time = timezone.now()
    
    # ----------------------------
    # 1️⃣ OPERATIONAL ALERTS
    # ----------------------------
    
    # Test 1: Unassigned orders
    try:
        from canadrop_interface.models import DeliveryOrder
        
        unassigned_orders = DeliveryOrder.objects.filter(
            driver__isnull=True,
            status__in=["pending", "accepted"]
        )[:20]
        
        for order in unassigned_orders:
            pharmacy_name = "Unknown"
            try:
                if order.pharmacy:
                    pharmacy_name = order.pharmacy.name
            except:
                pass
                
            alerts["operational"].append({
                "type": "Unassigned Order",
                "message": f"Order #{order.id} from {pharmacy_name} has no assigned driver.",
                "order_id": order.id,
                "timestamp": str(order.created_at) if order.created_at else ""
            })
    except Exception as e:
        errors.append(f"Unassigned orders error: {str(e)}")
    
    # Test 2: Stuck orders
    try:
        from canadrop_interface.models import DeliveryOrder
        
        two_hours_ago = current_time - timedelta(hours=2)
        stuck_orders = DeliveryOrder.objects.filter(
            status__in=["inTransit", "picked_up"],
            updated_at__lt=two_hours_ago
        )[:20]
        
        for order in stuck_orders:
            pharmacy_name = "Unknown"
            try:
                if order.pharmacy:
                    pharmacy_name = order.pharmacy.name
            except:
                pass
                
            alerts["operational"].append({
                "type": "Stuck Order",
                "message": f"Order #{order.id} by {pharmacy_name} is '{order.status}' for over 2 hours.",
                "order_id": order.id,
                "timestamp": str(order.updated_at) if order.updated_at else ""
            })
    except Exception as e:
        errors.append(f"Stuck orders error: {str(e)}")
    
    # Test 3: Inactive drivers with orders
    try:
        from canadrop_interface.models import DeliveryOrder
        
        orders_with_drivers = DeliveryOrder.objects.filter(
            driver__isnull=False,
            status__in=["pending", "accepted", "inTransit"]
        )[:50]
        
        for order in orders_with_drivers:
            try:
                if order.driver and hasattr(order.driver, 'active') and order.driver.active == False:
                    alerts["operational"].append({
                        "type": "Inactive Driver Assigned",
                        "message": f"Inactive driver {order.driver.name} still has order #{order.id}.",
                        "order_id": order.id,
                        "timestamp": str(order.updated_at) if order.updated_at else ""
                    })
            except:
                pass
    except Exception as e:
        errors.append(f"Inactive driver orders error: {str(e)}")
    
    # Test 4: Inactive pharmacy orders
    try:
        from canadrop_interface.models import DeliveryOrder
        
        three_days_ago = current_time - timedelta(days=3)
        recent_orders = DeliveryOrder.objects.filter(
            pharmacy__isnull=False,
            created_at__gte=three_days_ago
        )[:50]
        
        for order in recent_orders:
            try:
                if order.pharmacy and hasattr(order.pharmacy, 'active') and order.pharmacy.active == False:
                    alerts["operational"].append({
                        "type": "Inactive Pharmacy Order",
                        "message": f"Inactive pharmacy {order.pharmacy.name} created order #{order.id}.",
                        "order_id": order.id,
                        "timestamp": str(order.created_at) if order.created_at else ""
                    })
            except:
                pass
    except Exception as e:
        errors.append(f"Inactive pharmacy orders error: {str(e)}")
    
    # ----------------------------
    # 2️⃣ FINANCIAL ALERTS
    # ----------------------------
    
    # Test 5: Overdue invoices
    try:
        from canadrop_interface.models import Invoice
        
        overdue_invoices = Invoice.objects.filter(status="past_due")[:20]
        
        for inv in overdue_invoices:
            pharmacy_name = "Unknown"
            try:
                if inv.pharmacy:
                    pharmacy_name = inv.pharmacy.name
            except:
                pass
            
            amount = 0
            try:
                amount = float(inv.total_amount)
            except:
                pass
                
            alerts["financial"].append({
                "type": "Overdue Invoice",
                "message": f"Invoice #{inv.id} for {pharmacy_name} is past due (${amount:.2f}).",
                "invoice_id": inv.id,
                "timestamp": str(inv.due_date) if inv.due_date else ""
            })
    except Exception as e:
        errors.append(f"Overdue invoices error: {str(e)}")
    
    # Test 6: Pending driver payouts
    try:
        from canadrop_interface.models import DriverInvoice
        
        today = current_time.date()
        pending_driver_invoices = DriverInvoice.objects.filter(
            status="generated",
            due_date__lt=today
        )[:20]
        
        for inv in pending_driver_invoices:
            driver_name = "Unknown"
            try:
                if inv.driver:
                    driver_name = inv.driver.name
            except:
                pass
            
            amount = 0
            try:
                amount = float(inv.total_amount)
            except:
                pass
                
            alerts["financial"].append({
                "type": "Pending Driver Payout",
                "message": f"Driver {driver_name}'s invoice #{inv.id} is pending (${amount:.2f}).",
                "invoice_id": inv.id,
                "timestamp": str(inv.due_date) if inv.due_date else ""
            })
    except Exception as e:
        errors.append(f"Pending driver invoices error: {str(e)}")
    
    # ----------------------------
    # 3️⃣ SUPPORT ALERTS
    # ----------------------------
    
    # Test 7: Old pending tickets
    try:
        from canadrop_interface.models import ContactAdmin
        
        forty_eight_hours_ago = current_time - timedelta(hours=48)
        old_pending_tickets = ContactAdmin.objects.filter(
            status="pending",
            created_at__lt=forty_eight_hours_ago
        )[:20]
        
        subject_map = {
            'account_creation': 'Account Creation Issue',
            'login_problem': 'Login / Authentication Problem',
            'password_reset': 'Password Reset Issue',
            'profile_update': 'Profile / Information Update Issue',
            'order_placement': 'Order Placement Issue',
            'order_cancellation': 'Order Cancellation Issue',
            'order_tracking': 'Order Tracking / Status Issue',
            'order_payment': 'Order Payment / Rate Issue',
            'pickup_issue': 'Pickup Issue by Driver',
            'delivery_delay': 'Delivery Delay',
            'delivery_incorrect': 'Incorrect Delivery / Item Issue',
            'driver_unavailable': 'Driver Unavailable / Assignment Issue',
            'invoice_generated': 'Invoice Generated Issue',
            'invoice_payment': 'Invoice Payment / Stripe Issue',
            'driver_invoice': 'Driver Invoice / Payment Issue',
            'technical_bug': 'Technical / App Bug',
            'cloud_storage': 'Cloud / Image Upload Issue',
            'notification': 'Notification / Alert Issue',
            'feedback': 'Feedback / Suggestion',
            'other': 'Other',
        }
        
        for ticket in old_pending_tickets:
            sender = "Unknown"
            try:
                if ticket.pharmacy:
                    sender = ticket.pharmacy.name
                elif ticket.driver:
                    sender = ticket.driver.name
            except:
                pass
            
            subject_display = subject_map.get(ticket.subject, ticket.subject)
            if ticket.subject == 'other' and ticket.other_subject:
                subject_display = ticket.other_subject
                
            alerts["support"].append({
                "type": "Old Pending Ticket",
                "message": f"Ticket '{subject_display}' from {sender} pending > 48 hours.",
                "ticket_id": ticket.id,
                "timestamp": str(ticket.created_at) if ticket.created_at else ""
            })
    except Exception as e:
        errors.append(f"Old pending tickets error: {str(e)}")
    
    # Test 8: Unresponded tickets
    try:
        from canadrop_interface.models import ContactAdmin
        
        in_progress_tickets = ContactAdmin.objects.filter(status="in_progress")[:50]
        
        subject_map = {
            'account_creation': 'Account Creation Issue',
            'login_problem': 'Login / Authentication Problem',
            'password_reset': 'Password Reset Issue',
            'profile_update': 'Profile / Information Update Issue',
            'order_placement': 'Order Placement Issue',
            'order_cancellation': 'Order Cancellation Issue',
            'order_tracking': 'Order Tracking / Status Issue',
            'order_payment': 'Order Payment / Rate Issue',
            'pickup_issue': 'Pickup Issue by Driver',
            'delivery_delay': 'Delivery Delay',
            'delivery_incorrect': 'Incorrect Delivery / Item Issue',
            'driver_unavailable': 'Driver Unavailable / Assignment Issue',
            'invoice_generated': 'Invoice Generated Issue',
            'invoice_payment': 'Invoice Payment / Stripe Issue',
            'driver_invoice': 'Driver Invoice / Payment Issue',
            'technical_bug': 'Technical / App Bug',
            'cloud_storage': 'Cloud / Image Upload Issue',
            'notification': 'Notification / Alert Issue',
            'feedback': 'Feedback / Suggestion',
            'other': 'Other',
        }
        
        for ticket in in_progress_tickets:
            try:
                if not ticket.admin_response or ticket.admin_response.strip() == "":
                    subject_display = subject_map.get(ticket.subject, ticket.subject)
                    if ticket.subject == 'other' and ticket.other_subject:
                        subject_display = ticket.other_subject
                        
                    alerts["support"].append({
                        "type": "Unresponded Ticket",
                        "message": f"'{subject_display}' ticket has no admin response yet.",
                        "ticket_id": ticket.id,
                        "timestamp": str(ticket.updated_at) if ticket.updated_at else ""
                    })
            except:
                pass
    except Exception as e:
        errors.append(f"Unresponded tickets error: {str(e)}")
    
    # ----------------------------
    # ✅ Return Response
    # ----------------------------
    total_alerts = sum(len(v) for v in alerts.values())
    
    return JsonResponse({
        "success": True,
        "total_alerts": total_alerts,
        "categories": {k: len(v) for k, v in alerts.items()},
        "alerts": alerts,
        "generated_at": str(current_time),
        "errors": errors if errors else None
    }, status=200)





@csrf_exempt
def admin_order_list(request):
    """
    Returns all delivery orders - simple version with relative imports
    """
    try:
        orders = list(DeliveryOrder.objects.all().order_by("pickup_day").values(
            'id',
            'pharmacy_id',
            'driver_id', 
            'pickup_address',
            'pickup_city',
            'pickup_day',
            'drop_address',
            'drop_city',
            'status',
            'rate',
            'customer_name',
            'created_at',
            'updated_at'
        ))
        
        result = []
        
        for order in orders:
            # Get pharmacy info
            pharmacy_info = None
            if order.get('pharmacy_id'):
                try:
                    p = Pharmacy.objects.filter(id=order['pharmacy_id']).values(
                        'id', 'name', 'email', 'phone_number', 
                        'city', 'province', 'postal_code', 'country', 
                        'active', 'created_at'
                    ).first()
                    if p:
                        pharmacy_info = {
                            "id": p['id'],
                            "name": p['name'],
                            "email": p['email'],
                            "phone_number": p['phone_number'],
                            "city": p['city'],
                            "province": p['province'],
                            "postal_code": p['postal_code'],
                            "country": p['country'],
                            "active": p['active'],
                            "created_at": str(p['created_at'])
                        }
                except:
                    pass
            
            # Get driver info
            driver_info = None
            if order.get('driver_id'):
                try:
                    d = Driver.objects.filter(id=order['driver_id']).values(
                        'id', 'name', 'email', 'phone_number',
                        'vehicle_number', 'active', 'created_at'
                    ).first()
                    if d:
                        driver_info = {
                            "id": d['id'],
                            "name": d['name'],
                            "email": d['email'],
                            "phone_number": d['phone_number'],
                            "vehicle_number": d['vehicle_number'],
                            "active": d['active'],
                            "created_at": str(d['created_at'])
                        }
                except:
                    pass
            
            # Get tracking
            tracking_info = []
            try:
                tracks = OrderTracking.objects.filter(order_id=order['id']).order_by('timestamp').values(
                    'step', 'performed_by', 'timestamp', 'note', 'image_url'
                )
                for t in tracks:
                    tracking_info.append({
                        "step": t['step'],
                        "performed_by": t['performed_by'] or "",
                        "timestamp": str(t['timestamp']),
                        "note": t['note'] or "",
                        "image_url": t['image_url'] or ""
                    })
            except:
                pass
            
            # Get images
            proof_images = []
            try:
                imgs = OrderImage.objects.filter(order_id=order['id']).order_by('uploaded_at').values(
                    'stage', 'image_url', 'uploaded_at'
                )
                for img in imgs:
                    proof_images.append({
                        "stage": img['stage'],
                        "image_url": img['image_url'],
                        "uploaded_at": str(img['uploaded_at'])
                    })
            except:
                pass
            
            # Calculate commission
            rate = float(order['rate']) if order['rate'] else 0.0
            commission = round(rate * settings.DRIVER_COMMISSION_RATE, 2)  # ✅ FIXED
            net = round(rate - commission, 2)
            
            result.append({
                "order_id": order['id'],
                "pharmacy": pharmacy_info,
                "driver": driver_info,
                "pickup_address": order['pickup_address'] or "",
                "pickup_city": order['pickup_city'] or "",
                "pickup_day": str(order['pickup_day']) if order['pickup_day'] else "",
                "drop_address": order['drop_address'] or "",
                "drop_city": order['drop_city'] or "",
                "status": order['status'] or "",
                "amount": rate,
                "customer_name": order['customer_name'] or "",
                "created_at": str(order['created_at']) if order['created_at'] else "",
                "updated_at": str(order['updated_at']) if order['updated_at'] else "",
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
            "total_orders": len(result),
            "orders": result
        }, safe=False)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)



@csrf_exempt
def delivery_rates_list(request):
    """
    GET /api/deliveryRates/ -> returns all delivery distance rates.
    """
    if request.method != "GET":
        return JsonResponse({"success": False, "error": "Only GET allowed"}, status=405)

    try:
        from .models import DeliveryDistanceRate
        
        rates = DeliveryDistanceRate.objects.all().order_by("min_distance_km")
        
        data = []
        for r in rates:
            try:
                min_km = float(r.min_distance_km) if r.min_distance_km else 0.0
            except:
                min_km = 0.0
            
            try:
                max_km = float(r.max_distance_km) if r.max_distance_km else None
            except:
                max_km = None
            
            try:
                rate_val = float(r.rate) if r.rate else 0.0
            except:
                rate_val = 0.0
            
            # Build label
            if max_km:
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
            "rates": data
        }, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__
        }, status=500)




@csrf_exempt
def edit_order(request, order_id):
    """
    PUT /api/editOrder/<order_id>/
    Updates allowed editable fields in DeliveryOrder.
    Editable fields:
      - pickup_address
      - pickup_city
      - drop_address
      - drop_city
      - rate
      - status
      - customer_name
      - pickup_day
    """
    if request.method not in ["PUT", "POST"]:
        return JsonResponse({"success": False, "error": "Only PUT or POST allowed"}, status=405)

    try:
        body = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON body"}, status=400)

    try:
        order = DeliveryOrder.objects.get(id=order_id)
    except DeliveryOrder.DoesNotExist:
        return JsonResponse({"success": False, "error": f"Order ID {order_id} not found"}, status=404)

    editable_fields = [
        "pickup_address", "pickup_city", "drop_address", "drop_city",
        "rate", "status", "customer_name", "pickup_day"
    ]

    # Apply updates if provided
    for field in editable_fields:
        if field in body and body[field] is not None:
            try:
                if field == "pickup_day":
                    order.pickup_day = parse_date(str(body[field]))
                elif field == "rate":
                    order.rate = float(body[field])
                else:
                    setattr(order, field, body[field])
            except Exception as e:
                return JsonResponse({"success": False, "error": f"Invalid value for {field}: {str(e)}"}, status=400)

    order.save()

    # Build response
    updated_data = {
        "order_id": order.id,
        "pickup_address": order.pickup_address,
        "pickup_city": order.pickup_city,
        "drop_address": order.drop_address,
        "drop_city": order.drop_city,
        "rate": float(order.rate),
        "status": order.status,
        "customer_name": order.customer_name,
        "pickup_day": str(order.pickup_day),
        "updated_at": str(order.updated_at),
    }

    return JsonResponse({"success": True, "message": "Order updated successfully", "order": updated_data}, status=200)



@csrf_exempt
def cancel_order(request, order_id: int):
    """
    Cancels an order (soft delete) by updating status='cancelled'
    and always adds an OrderTracking entry for auditing.
    Accepts DELETE or POST.
    """
    if request.method not in ("DELETE", "POST"):
        return HttpResponseNotAllowed(["DELETE", "POST"])

    try:
        order = DeliveryOrder.objects.get(id=order_id)
    except DeliveryOrder.DoesNotExist:
        return JsonResponse({"success": False, "error": "Order not found."}, status=404)

    prev_status = order.status

    # Prevent cancelling delivered orders if needed
    if prev_status == "delivered":
        return JsonResponse({
            "success": False,
            "error": "Delivered orders cannot be cancelled."
        }, status=400)

    # Update order status and timestamp
    order.status = "cancelled"
    order.updated_at = timezone.now()
    order.save(update_fields=["status", "updated_at"])

    # Always add tracking entry
    OrderTracking.objects.create(
        order=order,
        driver=order.driver,
        pharmacy=order.pharmacy,
        step="cancelled",
        performed_by="admin_panel",
        note="Order cancelled via Admin Dashboard.",
        timestamp=timezone.now(),
    )

    # ---- Send cancellation email to pharmacy ----
    if order.pharmacy and order.pharmacy.email:
        try:
            brand_primary = settings.BRAND_COLORS['primary']
            brand_primary_dark = settings.BRAND_COLORS['primary_dark']
            brand_accent = settings.BRAND_COLORS['accent']
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
            logo_url = settings.LOGO_URL
            
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y") if order.pickup_day else "N/A"

            pharmacy_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Cancelled • CanaLogistiX</title>
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
                      <img src="{logo_url}" alt="CanaLogistiX" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
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
                        Thank you for using CanaLogistiX.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            pharmacy_text = (
                f"Order Cancelled - CanaLogistiX\n\n"
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
                subject=f"Order #{order.id} Cancelled • CanaLogistiX",
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
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
            logo_url = settings.LOGO_URL
            
            pickup_date_str = order.pickup_day.strftime("%A, %B %d, %Y") if order.pickup_day else "N/A"

            driver_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Order Cancelled • CanaLogistiX</title>
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
                      <img src="{logo_url}" alt="CanaLogistiX" width="64" height="64" style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
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
                        Thank you for being part of the CanaLogistiX team.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
          
          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            driver_text = (
                f"Order Cancelled - CanaLogistiX\n\n"
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
                subject=f"Order #{order.id} Cancelled • CanaLogistiX",
                to_email=order.driver.email,
                html=driver_html,
                text_fallback=driver_text,
            )
            
        except Exception as e:
            print(f"ERROR sending driver cancellation email: {str(e)}")
            import traceback
            traceback.print_exc()

    return JsonResponse({
        "success": True,
        "message": f"Order #{order.id} successfully cancelled.",
        "order_id": order.id,
        "previous_status": prev_status,
        "new_status": "cancelled",
        "updated_at": order.updated_at.isoformat(),
    }, status=200)





@csrf_exempt
@require_http_methods(["POST"])
def add_delivery_rate(request):
    """
    Create a new DeliveryDistanceRate row.

    Expected JSON body:
    {
      "min_distance_km": number (required, >= 0),
      "max_distance_km": number|null (optional, >= min_distance_km),
      "rate": number (required, >= 0)
    }
    """
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON body."},
            status=400,
        )

    # Extract fields
    min_km = payload.get("min_distance_km", None)
    max_km = payload.get("max_distance_km", None)  # can be None
    rate = payload.get("rate", None)

    # Basic validation & decimal conversion
    try:
        if min_km is None:
            return JsonResponse({"success": False, "error": "min_distance_km is required."}, status=400)
        if rate is None:
            return JsonResponse({"success": False, "error": "rate is required."}, status=400)

        min_km = Decimal(str(min_km))
        rate = Decimal(str(rate))

        if min_km < 0:
            return JsonResponse({"success": False, "error": "min_distance_km must be >= 0."}, status=400)
        if rate < 0:
            return JsonResponse({"success": False, "error": "rate must be >= 0."}, status=400)

        # max_km is optional (null means open-ended)
        if max_km is not None:
            max_km = Decimal(str(max_km))
            if max_km < min_km:
                return JsonResponse({"success": False, "error": "max_distance_km must be >= min_distance_km."}, status=400)
        else:
            max_km = None

    except InvalidOperation:
        return JsonResponse({"success": False, "error": "Distances/rate must be valid numbers."}, status=400)

    # (Optional) Simple overlap guard — comment out if you don't want it.
    # This checks for any interval overlap with existing rows.
    overlap_qs = DeliveryDistanceRate.objects.all()
    for r in overlap_qs:
        r_min = r.min_distance_km
        r_max = r.max_distance_km  # can be None (open-ended)
        # If both are ranges, overlap if (minA <= maxB or maxB is None) and (maxA is None or maxA >= minB)
        if (max_km is None or r_min <= max_km) and (r_max is None or r_max >= min_km):
            return JsonResponse(
                {
                    "success": False,
                    "error": f"New range ({min_km}–{max_km if max_km is not None else '∞'}) overlaps existing range "
                             f"({r_min}–{r_max if r_max is not None else '∞'}) [id={r.id}]."
                },
                status=409,
            )

    try:
        new_rate = DeliveryDistanceRate.objects.create(
            min_distance_km=min_km,
            max_distance_km=max_km,
            rate=rate,
        )

        return JsonResponse(
            {
                "success": True,
                "message": "Delivery rate added successfully.",
                "rate": {
                    "id": new_rate.id,
                    "min_distance_km": float(new_rate.min_distance_km),
                    "max_distance_km": float(new_rate.max_distance_km) if new_rate.max_distance_km is not None else None,
                    "rate": float(new_rate.rate),
                },
            },
            status=201,
        )
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)





# ✏️ EDIT DELIVERY RATE
@csrf_exempt
@require_http_methods(["PUT", "POST"])  # Allow both PUT and POST for compatibility
def edit_delivery_rate(request, rate_id):
    """
    Edit an existing DeliveryDistanceRate entry.
    URL: /api/deliveryRates/<id>/edit/
    
    Expected JSON body:
    {
      "min_distance_km": number (optional, >= 0),
      "max_distance_km": number|null (optional, >= min_distance_km),
      "rate": number (optional, >= 0)
    }
    """
    try:
        # Parse request body
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON payload."},
                status=400
            )

        # Check if rate exists
        try:
            rate_obj = DeliveryDistanceRate.objects.get(id=rate_id)
        except DeliveryDistanceRate.DoesNotExist:
            return JsonResponse(
                {"success": False, "error": f"Rate with ID {rate_id} not found."},
                status=404
            )

        # Extract fields
        min_km = payload.get("min_distance_km")
        max_km = payload.get("max_distance_km")
        rate = payload.get("rate")

        # Track if any changes were made
        changes_made = False

        # Update min_distance_km
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

        # Update max_distance_km
        if max_km is not None:
            if max_km == "" or max_km == "null":
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

        # Update rate
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

        if not changes_made:
            return JsonResponse(
                {"success": False, "message": "No fields were updated."},
                status=400
            )

        # Save changes
        rate_obj.save()

        # Build response
        response_data = {
            "success": True,
            "message": "Delivery rate updated successfully.",
            "rate": {
                "id": rate_obj.id,
                "min_distance_km": float(rate_obj.min_distance_km) if rate_obj.min_distance_km else 0.0,
                "max_distance_km": float(rate_obj.max_distance_km) if rate_obj.max_distance_km else None,
                "rate": float(rate_obj.rate) if rate_obj.rate else 0.0,
            },
        }

        return JsonResponse(response_data, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            "success": False,
            "error": f"Internal server error: {str(e)}",
            "error_type": type(e).__name__
        }, status=500)


# 🗑️ DELETE DELIVERY RATE
@csrf_exempt
@require_http_methods(["DELETE", "POST"])  # Allow both DELETE and POST for compatibility
def delete_delivery_rate(request, rate_id):
    """
    Hard delete a DeliveryDistanceRate entry.
    URL: /api/deliveryRates/<id>/delete/
    """
    try:
        # Check if rate exists
        try:
            rate_obj = DeliveryDistanceRate.objects.get(id=rate_id)
        except DeliveryDistanceRate.DoesNotExist:
            return JsonResponse(
                {"success": False, "error": f"Rate with ID {rate_id} not found."},
                status=404
            )

        # Store info before deletion for response
        rate_info = {
            "id": rate_obj.id,
            "min_distance_km": float(rate_obj.min_distance_km) if rate_obj.min_distance_km else 0.0,
            "max_distance_km": float(rate_obj.max_distance_km) if rate_obj.max_distance_km else None,
            "rate": float(rate_obj.rate) if rate_obj.rate else 0.0,
        }

        # Delete the rate
        rate_obj.delete()

        return JsonResponse({
            "success": True,
            "message": f"Rate ID {rate_id} deleted successfully.",
            "deleted_rate": rate_info
        }, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({
            "success": False,
            "error": f"Internal server error: {str(e)}",
            "error_type": type(e).__name__
        }, status=500)







@csrf_exempt
def get_pharmacy_details_admin(request, pharmacy_id=None):
    try:
        # 🟠 CASE 1: No ID → return ALL pharmacies (summary)
        if pharmacy_id is None:
            pharmacies = Pharmacy.objects.all().order_by("name")

            pharmacy_list = []
            for p in pharmacies:
                total_orders = DeliveryOrder.objects.filter(
                    pharmacy=p
                ).exclude(status="cancelled").count()

                total_outstanding = Invoice.objects.filter(
                    pharmacy=p
                ).exclude(status="paid").aggregate(
                    total=Sum("total_amount")
                )["total"] or 0

                pharmacy_list.append({
                    "id": p.id,
                    "name": p.name,
                    "store_address" : p.store_address,
                    "city": p.city,
                    "postal_code" : p.postal_code,
                    "province": p.province,
                    "phone_number": p.phone_number,
                    "email": p.email,
                    "active": p.active,
                    "total_valid_orders": total_orders,
                    "total_outstanding_amount": float(total_outstanding),
                })

            return JsonResponse({
                "success": True,
                "pharmacies": pharmacy_list,
            }, status=200)

        # 🟢 CASE 2: ID provided → return SINGLE pharmacy with full info
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)

        total_orders = DeliveryOrder.objects.filter(
            pharmacy=pharmacy
        ).exclude(status="cancelled").count()

        total_outstanding = Invoice.objects.filter(
            pharmacy=pharmacy
        ).exclude(status="paid").aggregate(
            total=Sum("total_amount")
        )["total"] or 0

        orders_qs = DeliveryOrder.objects.filter(
            pharmacy=pharmacy
        ).order_by("-created_at")

        orders = []
        for o in orders_qs:
            orders.append({
                "id": o.id,
                "pickup_address": o.pickup_address,
                "pickup_city": o.pickup_city,
                "pickup_day": str(o.pickup_day),
                "drop_address": o.drop_address,
                "drop_city": o.drop_city,
                "status": o.status,
                "rate": float(o.rate),
                "customer_name": o.customer_name,
                "driver": o.driver.name if o.driver else None,
                "created_at": o.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": o.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

        invoice_qs = Invoice.objects.filter(
            pharmacy=pharmacy
        ).order_by("-created_at")

        invoices = []
        for inv in invoice_qs:
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
            })

        pharmacy_data = {
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
            "created_at": pharmacy.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse({
            "success": True,
            "pharmacy": pharmacy_data,
            "total_valid_orders": total_orders,
            "total_outstanding_amount": float(total_outstanding),
            "orders": orders,
            "invoices": invoices,
        }, status=200)

    except Pharmacy.DoesNotExist:
        return JsonResponse({"success": False, "message": "Pharmacy not found"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



@csrf_exempt
def get_driver_details_admin(request, driver_id=None):
    try:
        # 🟠 CASE 1: No ID → return ALL drivers (summary)
        if driver_id is None:
            drivers = Driver.objects.all().order_by("name")

            driver_list = []
            for d in drivers:
                total_deliveries = DeliveryOrder.objects.filter(
                    driver=d
                ).exclude(status="cancelled").count()

                total_earnings = DriverInvoice.objects.filter(
                    driver=d
                ).exclude(status="paid").aggregate(
                    total=Sum("total_amount")
                )["total"] or 0

                driver_list.append({
                    "id": d.id,
                    "name": d.name,
                    "phone_number": d.phone_number,
                    "email": d.email,
                    "vehicle_number": d.vehicle_number,
                    "active": d.active,
                    "total_completed_deliveries": total_deliveries,
                    "total_outstanding_amount": float(total_earnings),
                })

            return JsonResponse({
                "success": True,
                "drivers": driver_list,
            }, status=200)

        # 🟢 CASE 2: ID provided → return SINGLE driver full info
        driver = Driver.objects.get(id=driver_id)

        total_deliveries = DeliveryOrder.objects.filter(
            driver=driver
        ).exclude(status="cancelled").count()

        total_earnings = DriverInvoice.objects.filter(
            driver=driver
        ).exclude(status="paid").aggregate(
            total=Sum("total_amount")
        )["total"] or 0

        # Fetch driver orders
        orders_qs = DeliveryOrder.objects.filter(
            driver=driver
        ).order_by("-created_at")

        orders = []
        for o in orders_qs:
            # Fetch order images
            images = [
                {
                    "id": img.id,
                    "stage": img.stage,
                    "image_url": img.image_url,
                    "uploaded_at": img.uploaded_at.strftime("%Y-%m-%d %H:%M:%S")
                }
                for img in o.images.all()
            ]

            # Fetch tracking entries
            tracking_entries = [
                {
                    "id": t.id,
                    "step": t.step,
                    "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "performed_by": t.performed_by,
                    "note": t.note,
                    "image_url": t.image_url,
                    "pharmacy": t.pharmacy.name if t.pharmacy else None,
                }
                for t in o.tracking_entries.all()
            ]

            orders.append({
                "id": o.id,
                "pharmacy": o.pharmacy.name,
                "pickup_address": o.pickup_address,
                "pickup_city": o.pickup_city,
                "pickup_day": str(o.pickup_day),
                "drop_address": o.drop_address,
                "drop_city": o.drop_city,
                "status": o.status,
                "rate": float(o.rate),
                "customer_name": o.customer_name,
                "created_at": o.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": o.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                "images": images,
                "tracking_entries": tracking_entries,
            })

        # Fetch driver invoices
        invoice_qs = DriverInvoice.objects.filter(
            driver=driver
        ).order_by("-created_at")

        invoices = []
        for inv in invoice_qs:
            invoices.append({
                "invoice_id": inv.id,
                "start_date": str(inv.start_date),
                "end_date": str(inv.end_date),
                "total_deliveries": inv.total_deliveries,
                "total_amount": float(inv.total_amount),
                "due_date": str(inv.due_date),
                "status": inv.status,
                "pdf_url": inv.pdf_url,
            })

        driver_data = {
            "id": driver.id,
            "name": driver.name,
            "phone_number": driver.phone_number,
            "email": driver.email,
            "vehicle_number": driver.vehicle_number,
            "active": driver.active,
            "created_at": driver.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse({
            "success": True,
            "driver": driver_data,
            "total_completed_deliveries": total_deliveries,
            "total_outstanding_amount": float(total_earnings),
            "orders": orders,
            "invoices": invoices,
        }, status=200)

    except Driver.DoesNotExist:
        return JsonResponse({"success": False, "message": "Driver not found"}, status=404)

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



@csrf_exempt
def add_pharmacy(request):
    if request.method != "POST":
        return JsonResponse(
            {"success": False, "message": "Only POST method is allowed."},
            status=405,
        )

    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

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

    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return JsonResponse(
            {
                "success": False,
                "message": "Missing required fields.",
                "missing_fields": missing,
            },
            status=400,
        )

    try:
        pharmacy = Pharmacy.objects.create(
            name=data.get("name").strip(),
            store_address=data.get("store_address").strip(),
            city=data.get("city").strip(),
            province=data.get("province").strip(),
            postal_code=data.get("postal_code").strip(),
            country=data.get("country").strip(),
            phone_number=data.get("phone_number").strip(),
            email=data.get("email").strip(),
            # password: will use default "123456"
            # active: defaults to True (can override from payload if needed)
            active=data.get("active", True),
        )

        # Build response without password
        pharmacy_data = {
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
            "created_at": pharmacy.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse(
            {
                "success": True,
                "message": "Pharmacy created successfully.",
                "pharmacy": pharmacy_data,
            },
            status=201,
        )

    except IntegrityError:
        # Likely unique email constraint
        return JsonResponse(
            {
                "success": False,
                "message": "A pharmacy with this email already exists.",
                "field": "email",
            },
            status=400,
        )
    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500,
        )



@csrf_exempt
def add_driver(request):
    if request.method != "POST":
        return JsonResponse(
            {"success": False, "message": "Only POST method is allowed."},
            status=405,
        )

    # Parse JSON
    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

    # Required fields
    required_fields = [
        "name",
        "phone_number",
        "email",
    ]

    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return JsonResponse(
            {
                "success": False,
                "message": "Missing required fields.",
                "missing_fields": missing,
            },
            status=400,
        )

    try:
        driver = Driver.objects.create(
            name=data.get("name").strip(),
            phone_number=data.get("phone_number").strip(),
            email=data.get("email").strip(),
            vehicle_number=data.get("vehicle_number", "").strip(),
            # Password auto defaults to "123456"
            # Active defaults to True unless provided
            active=data.get("active", True),
        )

        driver_data = {
            "id": driver.id,
            "name": driver.name,
            "phone_number": driver.phone_number,
            "email": driver.email,
            "vehicle_number": driver.vehicle_number,
            "active": driver.active,
            "created_at": driver.created_at.strftime("%Y-%m-%d %H:%M:%S"),
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
        # Unique email violation
        return JsonResponse(
            {
                "success": False,
                "message": "A driver with this email already exists.",
                "field": "email",
            },
            status=400,
        )
    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500,
        )



@csrf_exempt
def edit_pharmacy(request, pharmacy_id):
    if request.method != "PUT":
        return JsonResponse(
            {"success": False, "message": "Only PUT method is allowed."},
            status=405,
        )

    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Pharmacy not found."},
            status=404,
        )

    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

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
        "active",
    ]

    # Update only provided fields
    for field in editable_fields:
        if field in data:
            setattr(pharmacy, field, data[field].strip() if isinstance(data[field], str) else data[field])

    try:
        pharmacy.save()

        updated_data = {
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
            "created_at": pharmacy.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse(
            {
                "success": True,
                "message": "Pharmacy updated successfully.",
                "pharmacy": updated_data,
            },
            status=200,
        )

    except IntegrityError:
        return JsonResponse(
            {
                "success": False,
                "message": "A pharmacy with this email already exists.",
                "field": "email",
            },
            status=400,
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500,
        )



@csrf_exempt
def edit_driver(request, driver_id):
    if request.method != "PUT":
        return JsonResponse(
            {"success": False, "message": "Only PUT method is allowed."},
            status=405,
        )

    try:
        driver = Driver.objects.get(id=driver_id)
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver not found."},
            status=404,
        )

    try:
        data = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "message": "Invalid JSON payload."},
            status=400,
        )

    # Editable fields for Driver
    editable_fields = [
        "name",
        "phone_number",
        "email",
        "vehicle_number",
        "active",
    ]

    # Update only provided fields
    for field in editable_fields:
        if field in data:
            setattr(
                driver,
                field,
                data[field].strip() if isinstance(data[field], str) else data[field],
            )

    try:
        driver.save()

        updated_data = {
            "id": driver.id,
            "name": driver.name,
            "phone_number": driver.phone_number,
            "email": driver.email,
            "vehicle_number": driver.vehicle_number,
            "active": driver.active,
            "created_at": driver.created_at.strftime("%Y-%m-%d %H:%M:%S"),
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
        return JsonResponse(
            {
                "success": False,
                "message": "A driver with this email already exists.",
                "field": "email",
            },
            status=400,
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500,
        )


@csrf_exempt
def toggle_pharmacy_status(request, pharmacy_id):
    if request.method not in ["POST", "PATCH"]:
        return JsonResponse(
            {"success": False, "message": "Only POST or PATCH method is allowed."},
            status=405,
        )

    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Pharmacy not found."},
            status=404,
        )

    # Try to read JSON body (optional)
    new_status = None
    try:
        if request.body:
            data = json.loads(request.body.decode("utf-8"))
            if "active" in data:
                new_status = bool(data["active"])
    except json.JSONDecodeError:
        # Ignore bad JSON, we’ll just toggle instead
        pass

    # If active explicitly provided → set it, else toggle
    if new_status is not None:
        pharmacy.active = new_status
    else:
        pharmacy.active = not pharmacy.active

    pharmacy.save()

    return JsonResponse(
        {
            "success": True,
            "message": "Pharmacy activated." if pharmacy.active else "Pharmacy deactivated.",
            "pharmacy": {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "active": pharmacy.active,
            },
        },
        status=200,
    )



@csrf_exempt
def toggle_driver_status(request, driver_id):
    if request.method not in ["POST", "PATCH"]:
        return JsonResponse(
            {"success": False, "message": "Only POST or PATCH method is allowed."},
            status=405,
        )

    try:
        driver = Driver.objects.get(id=driver_id)
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver not found."},
            status=404,
        )

    # Try to read JSON body (optional)
    new_status = None
    try:
        if request.body:
            data = json.loads(request.body.decode("utf-8"))
            if "active" in data:
                new_status = bool(data["active"])
    except json.JSONDecodeError:
        # Ignore bad JSON, we'll just toggle instead
        pass

    # If active explicitly provided → set it, else toggle
    if new_status is not None:
        driver.active = new_status
    else:
        driver.active = not driver.active

    driver.save()

    return JsonResponse(
        {
            "success": True,
            "message": "Driver activated." if driver.active else "Driver deactivated.",
            "driver": {
                "id": driver.id,
                "name": driver.name,
                "active": driver.active,
            },
        },
        status=200,
    )




@csrf_exempt
def reset_pharmacy_password(request, pharmacy_id):
    if request.method not in ["POST", "PATCH"]:
        return JsonResponse(
            {"success": False, "message": "Only POST or PATCH method is allowed."},
            status=405,
        )

    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
    except Pharmacy.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Pharmacy not found."},
            status=404,
        )

    # Reset password to default — your model will hash it automatically
    pharmacy.password = "123456"
    pharmacy.save()

    return JsonResponse(
        {
            "success": True,
            "message": "Password reset successfully.",
            "pharmacy": {
                "id": pharmacy.id,
                "name": pharmacy.name,
                "email": pharmacy.email,
                "active": pharmacy.active,
            },
        },
        status=200,
    )



@csrf_exempt
def reset_driver_password(request, driver_id):
    if request.method not in ["POST", "PATCH"]:
        return JsonResponse(
            {"success": False, "message": "Only POST or PATCH method is allowed."},
            status=405,
        )

    try:
        driver = Driver.objects.get(id=driver_id)
    except Driver.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "Driver not found."},
            status=404,
        )

    # Reset password to default — model will hash it automatically
    driver.password = "123456"
    driver.save()

    return JsonResponse(
        {
            "success": True,
            "message": "Password reset successfully.",
            "driver": {
                "id": driver.id,
                "name": driver.name,
                "email": driver.email,
                "active": driver.active,
            },
        },
        status=200,
    )



@csrf_exempt
def get_all_pharmacy_invoices(request):
    """
    Returns ALL pharmacy invoices with full details.
    """
    if request.method != "GET":
        return JsonResponse(
            {"success": False, "message": "Only GET method is allowed."},
            status=405,
        )

    try:
        # Fetch all invoices with related pharmacy details
        invoices_qs = Invoice.objects.select_related("pharmacy").order_by("-created_at")

        invoices_list = []
        for inv in invoices_qs:
            invoices_list.append({
                "invoice_id": inv.id,
                "pharmacy_id": inv.pharmacy.id,
                "pharmacy_name": inv.pharmacy.name,

                "period": {
                    "start_date": str(inv.start_date),
                    "end_date": str(inv.end_date),
                },

                "total_orders": inv.total_orders,
                "total_amount": float(inv.total_amount),
                "due_date": str(inv.due_date),
                "status": inv.status,
                "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M:%S"),

                "pdf_url": inv.pdf_url,
                "stripe_payment_id": inv.stripe_payment_id,
            })

        return JsonResponse(
            {
                "success": True,
                "invoices": invoices_list,
                "count": len(invoices_list),
            },
            status=200,
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500,
        )



@csrf_exempt
def get_all_driver_invoices(request):
    if request.method != "GET":
        return JsonResponse(
            {"success": False, "message": "Only GET method is allowed."},
            status=405,
        )

    try:
        invoices = DriverInvoice.objects.select_related("driver").order_by("-created_at")

        invoice_list = []
        for inv in invoices:
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

                # Meta
                "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

        return JsonResponse(
            {"success": True, "invoices": invoice_list},
            status=200
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500
        )



@csrf_exempt
def get_payment_alerts(request):
    """
    Returns all payment alerts from:
    - Pharmacy Invoices (past_due or due soon)
    - Driver Invoices (generated & due soon or overdue)
    """

    try:
        today = timezone.now().date()
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
                "days_left": (inv.due_date - today).days,  # negative
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

        # 🔶 3. Driver Invoices — Overdue (generated & due_date < today)
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
                "status": "past_due",  # marking via business logic
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

        # 🔽 Sort by urgency — overdue first, then soonest
        alerts.sort(key=lambda x: x["days_left"])

        return JsonResponse({
            "success": True,
            "count": len(alerts),
            "alerts": alerts
        }, status=200)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)


@csrf_exempt
def get_monthly_financials(request):
    """
    Returns 3 financial metrics:
    - revenue_this_month
    - driver_payout_this_month
    - net_commission (value + % of revenue)
    """
    try:
        today = date.today()

        # 1️⃣ Revenue this month → sum of order rate for delivered orders this month
        revenue_this_month = (
            DeliveryOrder.objects.filter(
                status='delivered',
                created_at__year=today.year,
                created_at__month=today.month
            ).aggregate(total=Sum('rate'))['total'] or 0
        )

        # 2️⃣ Driver payout this month → sum of driver invoices with start OR end in this month
        driver_payout_this_month = (
            DriverInvoice.objects.filter(
                Q(start_date__year=today.year, start_date__month=today.month) |
                Q(end_date__year=today.year, end_date__month=today.month)
            ).aggregate(total=Sum('total_amount'))['total'] or 0
        )

        # Convert to float
        revenue_float = float(revenue_this_month)
        payout_float = float(driver_payout_this_month)

        # 3️⃣ Net commission → Revenue - Payout
        net_commission_value = revenue_float - payout_float

        # % of revenue (avoid divide-by-zero)
        if revenue_float > 0:
            net_commission_percentage = (net_commission_value / revenue_float) * 100
        else:
            net_commission_percentage = 0.0

        return JsonResponse(
            {
                "success": True,
                "financials": {
                    "revenue_this_month": revenue_float,
                    "driver_payout_this_month": payout_float,
                    "net_commission": {
                        "value": net_commission_value,
                        "percentage_of_revenue": net_commission_percentage,
                    },
                }
            },
            status=200,
        )

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
def get_contact_ticket_details(request, ticket_id=None):
    try:
        # --------------------------------------------------
        # 1️⃣ CASE: RETURN ALL TICKETS
        # --------------------------------------------------
        if ticket_id is None:

            tickets = ContactAdmin.objects.all().order_by("-created_at")

            ticket_list = []

            for t in tickets:
                sender_type = "pharmacy" if t.pharmacy else "driver" if t.driver else "unknown"

                sender_info = None
                if t.pharmacy:
                    sender_info = {
                        "id": t.pharmacy.id,
                        "name": t.pharmacy.name,
                        "email": t.pharmacy.email,
                        "phone_number": t.pharmacy.phone_number,
                        "city": t.pharmacy.city,
                        "active": t.pharmacy.active,
                    }
                elif t.driver:
                    sender_info = {
                        "id": t.driver.id,
                        "name": t.driver.name,
                        "email": t.driver.email,
                        "phone_number": t.driver.phone_number,
                        "vehicle_number": t.driver.vehicle_number,
                        "active": t.driver.active,
                    }

                ticket_list.append({
                    "ticket_id": t.id,
                    "subject_key": t.subject,
                    "subject": t.get_subject_display() if t.subject != "other" else t.other_subject,
                    "status": t.status,
                    "message": t.message,
                    "admin_response": t.admin_response,
                    "sender_type": sender_type,
                    "sender": sender_info,
                    "created_at": t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "updated_at": t.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                })

            return JsonResponse({"success": True, "tickets": ticket_list}, status=200)

        # --------------------------------------------------
        # 2️⃣ CASE: RETURN SINGLE TICKET
        # --------------------------------------------------
        ticket = ContactAdmin.objects.get(id=ticket_id)

        sender_type = "pharmacy" if ticket.pharmacy else "driver" if ticket.driver else "unknown"

        # sender info details
        if ticket.pharmacy:
            sender_info = {
                "id": ticket.pharmacy.id,
                "name": ticket.pharmacy.name,
                "email": ticket.pharmacy.email,
                "phone_number": ticket.pharmacy.phone_number,
                "city": ticket.pharmacy.city,
                "active": ticket.pharmacy.active,
            }
        elif ticket.driver:
            sender_info = {
                "id": ticket.driver.id,
                "name": ticket.driver.name,
                "email": ticket.driver.email,
                "phone_number": ticket.driver.phone_number,
                "vehicle_number": ticket.driver.vehicle_number,
                "active": ticket.driver.active,
            }
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
            "created_at": ticket.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": ticket.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return JsonResponse({"success": True, "ticket": ticket_data}, status=200)

    except ContactAdmin.DoesNotExist:
        return JsonResponse({"success": False, "message": "Ticket not found"}, status=404)

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



@csrf_exempt
def update_ticket_status(request, ticket_id):
    """
    Update the status of a ContactAdmin ticket.

    Expects JSON body:
    {
        "status": "pending" | "in_progress" | "resolved"
    }
    """
    if request.method not in ["POST", "PATCH"]:
        return JsonResponse(
            {"success": False, "message": "Only POST or PATCH method is allowed."},
            status=405,
        )

    # 1️⃣ Fetch ticket
    try:
        ticket = ContactAdmin.objects.get(id=ticket_id)
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
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
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
    <title>Ticket Status Updated • CanaLogistiX</title>
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
                           alt="CanaLogistiX"
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
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                "Ticket Status Updated - CanaLogistiX\n\n"
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

    # 6️⃣ Build response
    return JsonResponse(
        {
            "success": True,
            "message": "Ticket status updated successfully.",
            "ticket": {
                "ticket_id": ticket.id,
                "status": ticket.status,
                "subject_key": ticket.subject,
                "subject": ticket.get_subject_display() if ticket.subject != "other" else ticket.other_subject,
                "updated_at": ticket.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=200,
    )


@csrf_exempt
def add_admin_response(request, ticket_id):
    """
    Adds an admin response to a ticket.
    Automatically sets the status to 'resolved' if not already resolved.

    Expected JSON body:
    {
        "admin_response": "Your issue has been resolved..."
    }
    """
    if request.method not in ["POST", "PATCH"]:
        return JsonResponse(
            {"success": False, "message": "Only POST or PATCH allowed."},
            status=405
        )

    # 1️⃣ Fetch ticket
    try:
        ticket = ContactAdmin.objects.get(id=ticket_id)
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
    if not admin_response:
        return JsonResponse(
            {"success": False, "message": "Missing 'admin_response'."},
            status=400
        )

    # 3️⃣ Update fields
    ticket.admin_response = admin_response

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
            now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
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
    <title>Admin Response • CanaLogistiX</title>
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
                           alt="CanaLogistiX"
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
                        Thank you for contacting CanaLogistiX support. We're here to help!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
            text = (
                "Admin Response Received - CanaLogistiX\n\n"
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

    # Build sender info
    sender_type = "Pharmacy" if ticket.pharmacy else "Driver"
    sender_info = {
        "type": sender_type,
        "id": ticket.pharmacy.id if ticket.pharmacy else ticket.driver.id,
        "name": ticket.pharmacy.name if ticket.pharmacy else ticket.driver.name,
        "email": ticket.pharmacy.email if ticket.pharmacy else ticket.driver.email,
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
                "sender": sender_info,
                "created_at": ticket.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": ticket.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=200
    )


@csrf_exempt
def get_ticket_status_metrics(request):
    """
    Returns counts of tickets by status:
    - pending
    - in_progress
    - resolved
    """
    if request.method != "GET":
        return JsonResponse(
            {"success": False, "message": "Only GET method is allowed."},
            status=405,
        )

    try:
        pending_count = ContactAdmin.objects.filter(status="pending").count()
        in_progress_count = ContactAdmin.objects.filter(status="in_progress").count()
        resolved_count = ContactAdmin.objects.filter(status="resolved").count()
        total_count = pending_count + in_progress_count + resolved_count

        return JsonResponse(
            {
                "success": True,
                "metrics": {
                    "pending_tickets": pending_count,
                    "in_progress_tickets": in_progress_count,
                    "resolved_tickets": resolved_count,
                    "total_tickets": total_count,
                },
            },
            status=200,
        )

    except Exception as e:
        return JsonResponse(
            {"success": False, "message": "Something went wrong.", "error": str(e)},
            status=500,
        )



@csrf_exempt
@require_http_methods(["POST"])
def pharmacy_onboarding_api(request):
    """
    API endpoint to create a new pharmacy trial onboarding entry.
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
        'delivery_radius_km', 'trial_start_date', 'trial_duration_days'
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
            {"success": False, "error": "Consent must be given to proceed with onboarding"},
            status=400
        )
    
    # Create the pharmacy onboarding record
    try:
        pharmacy_onboarding = PharmacyTrialOnboarding.objects.create(
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

            same_day_cutoff_time=None,

            delivery_radius_km=int(data['delivery_radius_km']),

            signature_required=True,
            id_verification_required=False,
            special_delivery_instructions=data.get('special_delivery_instructions'),

            trial_start_date=datetime.strptime(
                data['trial_start_date'], "%Y-%m-%d"
            ).date(),

            trial_duration_days=int(data.get('trial_duration_days', 7)),

            agreed_delivery_fee=0.00,

            consent_given=bool(data.get('consent_given')),

            onboarding_notes=data.get('onboarding_notes'),
            status="trial",
        )
    except Exception as e:
        logger.exception("Failed to create pharmacy onboarding record")
        return JsonResponse(
            {"success": False, "error": str(e)},
            status=500
        )
    
    # Send welcome email
    try:
        # Calculate trial end date
        trial_start = datetime.strptime(data['trial_start_date'], '%Y-%m-%d').date()
        trial_end = trial_start + timedelta(days=int(data.get('trial_duration_days', 7)))
        
        brand_primary = settings.BRAND_COLORS['primary']
        brand_primary_dark = settings.BRAND_COLORS['primary_dark']
        brand_accent = settings.BRAND_COLORS['accent']
        logo_url = settings.LOGO_URL
        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
        
        delivery_type_map = {
            'same_day': 'Same-day',
            'next_day': 'Next-day',
            'both': 'Both'
        }
        delivery_type_display = delivery_type_map.get(data['preferred_delivery_type'], data['preferred_delivery_type'])
        
        contact_role_display = data['contact_role'].replace('_', ' ').title()

        html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to CanaLogistiX Trial Program</title>
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
      Welcome to CanaLogistiX Trial Program — Start your pharmacy delivery journey with us.
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
                           alt="CanaLogistiX"
                           width="64"
                           height="64"
                           style="display:block;border:0;outline:none;text-decoration:none;border-radius:50%;object-fit:cover;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Trial Registration Confirmed
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 26px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Welcome to CanaLogistiX! 🎉
                </h1>
                <p style="margin:0 0 16px;font:400 15px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Hi <strong>{data['contact_name']}</strong>,
                </p>
                <p style="margin:0 0 16px;font:400 15px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                  Thank you for registering <strong>{data['pharmacy_name']}</strong> for our Trial Program! We're excited to partner with you and revolutionize your pharmacy delivery operations.
                </p>

                <div style="margin:20px 0;background:#d1fae5;border:1px solid #10b981;border-radius:12px;padding:14px 18px;">
                  <p style="margin:0;font:500 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#065f46;">
                    ✓ <strong>Registration Successful</strong> — Your trial account has been created and will be activated on <strong>{trial_start.strftime('%B %d, %Y')}</strong>.
                  </p>
                </div>

                <h2 style="margin:28px 0 14px;font:700 20px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Trial Period Details
                </h2>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Trial Start Date</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{trial_start.strftime('%B %d, %Y')}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Trial End Date</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{trial_end.strftime('%B %d, %Y')}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Duration</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data.get('trial_duration_days', 7)} days</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Delivery Type</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{delivery_type_display}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Delivery Radius</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data['delivery_radius_km']} km</td>
                    </tr>
                  </table>
                </div>

                <h2 style="margin:28px 0 14px;font:700 20px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Key Features & Benefits
                </h2>

                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="margin:18px 0;">
                  <tr>
                    <td style="padding:12px 0;">
                      <table width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="width:32px;vertical-align:top;">
                            <div style="width:28px;height:28px;background:#d1fae5;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;">🚫</div>
                          </td>
                          <td style="padding-left:12px;">
                            <p style="margin:0 0 4px;font:600 15px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">No In-House Delivery Setup Required</p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">Focus on your pharmacy operations while we handle all delivery logistics.</p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:12px 0;">
                      <table width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="width:32px;vertical-align:top;">
                            <div style="width:28px;height:28px;background:#dbeafe;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;">💰</div>
                          </td>
                          <td style="padding-left:12px;">
                            <p style="margin:0 0 4px;font:600 15px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">Pay Per Delivery</p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">Only pay for successful deliveries — no hidden fees or upfront costs.</p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:12px 0;">
                      <table width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="width:32px;vertical-align:top;">
                            <div style="width:28px;height:28px;background:#fef3c7;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;">📸</div>
                          </td>
                          <td style="padding-left:12px;">
                            <p style="margin:0 0 4px;font:600 15px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">Image Proof of Delivery</p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">Photo verification for every delivery ensures accountability and peace of mind.</p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:12px 0;">
                      <table width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="width:32px;vertical-align:top;">
                            <div style="width:28px;height:28px;background:#e0e7ff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;">🔐</div>
                          </td>
                          <td style="padding-left:12px;">
                            <p style="margin:0 0 4px;font:600 15px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">Access to Secure Portal</p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">Real-time tracking, order management, and detailed analytics at your fingertips.</p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:12px 0;">
                      <table width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="width:32px;vertical-align:top;">
                            <div style="width:28px;height:28px;background:#fce7f3;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;">📄</div>
                          </td>
                          <td style="padding-left:12px;">
                            <p style="margin:0 0 4px;font:600 15px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">No Contracts</p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">Flexible service with no long-term commitments or binding agreements.</p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:12px 0;">
                      <table width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td style="width:32px;vertical-align:top;">
                            <div style="width:28px;height:28px;background:#dcfce7;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;">🎁</div>
                          </td>
                          <td style="padding-left:12px;">
                            <p style="margin:0 0 4px;font:600 15px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">Earn CC Points to Redeem</p>
                            <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#64748b;">Earn points on every delivery and redeem them to sell products through our platform.</p>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>

                <h2 style="margin:28px 0 14px;font:700 20px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Important Information
                </h2>

                <div style="margin:18px 0;background:#fef3c7;border:1px solid #fbbf24;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:600 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#92400e;">
                    ⚠️ Return Policy
                  </p>
                  <p style="margin:0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#78350f;">
                    If a delivery is unsuccessful, medications will be safely returned to your pharmacy on the same day of the delivery attempt. You'll be required to place another order on the portal.
                  </p>
                </div>

                <div style="margin:18px 0;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:600 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#334155;">
                    ℹ️ Portal Access
                  </p>
                  <p style="margin:0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                    You'll receive separate login credentials for the CanaLogistiX portal before your trial start date. The portal allows you to manage orders, track deliveries in real-time and access support.
                  </p>
                </div>

                <div style="margin:18px 0;background:#fef2f2;border:1px solid #fecaca;border-radius:12px;padding:16px 18px;">
                  <p style="margin:0 0 10px;font:600 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#991b1b;">
                    📋 Trial Disclaimer
                  </p>
                  <p style="margin:0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#7f1d1d;">
                    This is a trial period to evaluate our services. Either party may discontinue the service at the end of the trial period without penalty. All delivery operations will comply with applicable pharmacy regulations and privacy laws.
                  </p>
                </div>

                <h2 style="margin:28px 0 14px;font:700 20px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Your Registration Details
                </h2>

                <div style="margin:18px 0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:0;overflow:hidden;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="font:400 14px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;">
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;">Pharmacy Name</td>
                      <td style="padding:12px 18px;color:#0f172a;font-weight:500;">{data['pharmacy_name']}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Contact Person</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data['contact_name']} ({contact_role_display})</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Email</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data['pharmacy_email']}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Phone</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data['pharmacy_phone']}</td>
                    </tr>
                    <tr class="info-row" style="background:#f1f5f9;">
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Address</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data['address_line_1']}, {data['city']}, {data['postal_code']}</td>
                    </tr>
                    <tr>
                      <td style="padding:12px 18px;color:#64748b;font-weight:600;border-top:1px solid #e2e8f0;">Store Hours</td>
                      <td style="padding:12px 18px;color:#0f172a;border-top:1px solid #e2e8f0;">{data['store_hours']}</td>
                    </tr>
                  </table>
                </div>

                <h2 style="margin:28px 0 14px;font:700 20px/1.3 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#0f172a;">
                  Next Steps
                </h2>

                <div style="margin:18px 0;">
                  <table width="100%" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                      <td style="padding:8px 0;">
                        <table width="100%" cellspacing="0" cellpadding="0" border="0">
                          <tr>
                            <td style="width:24px;vertical-align:top;font:700 14px/1.4 system-ui;color:{brand_primary};">1.</td>
                            <td style="padding-left:8px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                              Watch for your portal login credentials (arriving before {trial_start.strftime('%B %d')})
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:8px 0;">
                        <table width="100%" cellspacing="0" cellpadding="0" border="0">
                          <tr>
                            <td style="width:24px;vertical-align:top;font:700 14px/1.4 system-ui;color:{brand_primary};">2.</td>
                            <td style="padding-left:8px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                              Our team will contact you to schedule a brief onboarding call
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:8px 0;">
                        <table width="100%" cellspacing="0" cellpadding="0" border="0">
                          <tr>
                            <td style="width:24px;vertical-align:top;font:700 14px/1.4 system-ui;color:{brand_primary};">3.</td>
                            <td style="padding-left:8px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#475569;">
                              Log in to the portal on {trial_start.strftime('%B %d')} and start processing deliveries
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                  </table>
                </div>

                <hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0;">
                <p class="muted" style="margin:0;font:400 13px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#6b7280;">
                  Questions about your trial? Our support team is here to help! Reach out to us anytime, and we'll get back to you promptly.
                </p>
              </td>
            </tr>

            <tr>
              <td style="padding:0 24px 24px;">
                <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background:linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);border:1px solid #86efac;border-radius:12px;">
                  <tr>
                    <td style="padding:16px 18px;">
                      <p style="margin:0 0 6px;font:600 14px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#166534;">
                        🚀 Ready to Transform Your Delivery Operations?
                      </p>
                      <p style="margin:0;font:400 13px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#15803d;">
                        We're excited to partner with you and show you how CanaLogistiX can streamline your pharmacy deliveries!
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>

          <p style="margin:14px 0 0;font:400 12px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#94a3b8;">
            © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

        text = (
            "Welcome to CanaLogistiX Trial Program!\n\n"
            f"Hi {data['contact_name']},\n\n"
            f"Thank you for registering {data['pharmacy_name']} for our Trial Program!\n\n"
            "TRIAL PERIOD DETAILS:\n"
            f"Trial Start Date: {trial_start.strftime('%B %d, %Y')}\n"
            f"Trial End Date: {trial_end.strftime('%B %d, %Y')}\n"
            f"Duration: {data.get('trial_duration_days', 7)} days\n"
            f"Delivery Type: {delivery_type_display}\n"
            f"Delivery Radius: {data['delivery_radius_km']} km\n\n"
            "KEY FEATURES & BENEFITS:\n"
            "• No In-House Delivery Setup Required\n"
            "• Pay Per Delivery — Only pay for successful deliveries\n"
            "• Image Proof of Delivery — Photo verification for every delivery\n"
            "• Access to Secure Portal — Real-time tracking and analytics\n"
            "• No Contracts — Flexible service with no commitments\n"
            "• Earn CC Points to Redeem — Earn points to sell products\n\n"
            "IMPORTANT INFORMATION:\n"
            "• Return Policy: Unsuccessful deliveries will be returned same day\n"
            "• Portal Access: Login credentials will arrive before trial start\n"
            "• Trial Disclaimer: Either party may discontinue after trial period\n\n"
            "YOUR REGISTRATION DETAILS:\n"
            f"Pharmacy: {data['pharmacy_name']}\n"
            f"Contact: {data['contact_name']} ({contact_role_display})\n"
            f"Email: {data['pharmacy_email']}\n"
            f"Phone: {data['pharmacy_phone']}\n"
            f"Address: {data['address_line_1']}, {data['city']}, {data['postal_code']}\n\n"
            "NEXT STEPS:\n"
            f"1. Watch for portal login credentials (arriving before {trial_start.strftime('%B %d')})\n"
            "2. Our team will contact you for a brief onboarding call\n"
            f"3. Log in on {trial_start.strftime('%B %d')} and start processing deliveries\n\n"
            "Questions? Our support team is here to help!\n"
        )

        _send_html_email_admin_office(
            subject=f"Welcome to CanaLogistiX Trial Program • {data['pharmacy_name']}",
            to_email=data['pharmacy_email'],
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send welcome email")
        # Don't fail the registration if email fails

    return JsonResponse(
        {
            "success": True,
            "message": f"Pharmacy '{pharmacy_onboarding.pharmacy_name}' onboarding submitted successfully!",
            "pharmacy": {
                "id": pharmacy_onboarding.id,
                "pharmacy_name": pharmacy_onboarding.pharmacy_name,
                "contact_name": pharmacy_onboarding.contact_name,
                "trial_start_date": pharmacy_onboarding.trial_start_date.strftime('%Y-%m-%d'),
                "trial_duration_days": pharmacy_onboarding.trial_duration_days,
                "status": pharmacy_onboarding.status,
                "created_at": pharmacy_onboarding.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        status=201
    )


@csrf_exempt
@require_http_methods(["GET"])
def get_pharmacy_cc_points(request, pharmacy_id):
    try:
        # 1) Delivered orders count (actual)
        delivered_orders_count = DeliveryOrder.objects.filter(
            pharmacy_id=pharmacy_id,
            status="delivered"
        ).count()

        # 2) Points from CCPointsAccount table (no multiplication)
        points_obj = CCPointsAccount.objects.filter(pharmacy_id=pharmacy_id).first()
        cc_points = points_obj.points_balance if points_obj else 0

        return JsonResponse({
            "success": True,
            "pharmacy_id": pharmacy_id,
            "delivered_orders": delivered_orders_count,
            "cc_points": cc_points
        })

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def upload_driver_identity_image(request):
    """
    Upload or replace a driver's identity/profile image to GCP
    (UBLA-safe) and store the public URL in Driver.identity_url
    """

    try:
        driver_id = request.POST.get("driverId")
        image_file = request.FILES.get("image")

        if not driver_id or not image_file:
            return JsonResponse({
                "success": False,
                "error": "driverId and image file are required"
            }, status=400)

        driver = get_object_or_404(Driver, id=driver_id)

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
        # Initialize GCP client (same style as working API)
        # ----------------------------
        credentials = service_account.Credentials.from_service_account_file(
            settings.GCP_KEY_PATH
        )

        client = storage.Client(credentials=credentials)
        bucket = client.bucket(settings.GCP_BUCKET_NAME)
        blob = bucket.blob(gcp_object_path)

        # Reset file pointer (important for safety)
        image_file.seek(0)

        # ----------------------------
        # Upload (overwrite if exists)
        # ----------------------------
        blob.upload_from_file(
            image_file,
            content_type=mimetypes.guess_type(filename)[0] or "image/jpeg"
        )

        # ----------------------------
        # UBLA-safe public URL (NO ACLs)
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
        })

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
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
    
    # Company info
    company_info = '''
    <para alignment="center">
    <font size="9" color="#64748B">CanaLogistiX Delivery Services<br/>
    Cana Group of Companies | Operating Name of CANABELLE INC.<br/>
    BN: 758568562 | help.canalogistix@gmail.com</font>
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
    
    current_date = timezone.now().strftime("%B %d, %Y at %I:%M %p")
    
    acknowledgement_text = f'''
    <para alignment="justify">
    <font size="10" color="#1E293B">
    I, <b>{order.customer_name}</b>, hereby acknowledge that I have received the pharmaceutical 
    delivery from <b>{order.pharmacy.name}</b> on <b>{current_date}</b>. 
    I confirm that all medicines have been received in <b>proper condition</b>, with intact packaging, 
    correct labeling, and no visible damage or tampering. The delivery was completed by 
    <b>CanaLogistiX Delivery Services</b> in accordance with pharmaceutical handling protocols.
    </font>
    </para>
    '''
    story.append(Paragraph(acknowledgement_text, body_style))
    story.append(Spacer(1, 25))
    
    # ==================== ORDER DETAILS ====================
    
    story.append(Paragraph("Order Information", section_header_style))
    
    order_details_data = [
        ['Order ID:', f"#{order.id}"],
        ['Order Date:', order.pickup_day.strftime("%B %d, %Y")],
        ['Delivery Date:', order.delivered_at.strftime("%B %d, %Y at %I:%M %p") if order.delivered_at else current_date],
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
    Service: CanaLogistiX<br/>
    Delivery Services</font>
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
    
    notice_text = '''
    <para alignment="justify">
    <font size="9" color="#64748B">
    This acknowledgement serves as proof of delivery and confirmation that all medicines were 
    received in acceptable condition. Any issues with the delivered medicines should be reported 
    immediately to the pharmacy and CanaLogistiX. By signing this document, the customer confirms 
    receipt and assumes responsibility for the proper storage and use of the delivered pharmaceutical products.
    </font>
    </para>
    '''
    story.append(Paragraph(notice_text, small_text_style))
    story.append(Spacer(1, 40))
    
    # ==================== FOOTER ====================
    
    footer_text = f'''
    <i>This acknowledgement was automatically generated by CanaLogistiX delivery system.<br/>
    Document ID: ACK-{order.id:06d} | Generated: {current_date}<br/>
    For questions or concerns, contact: help.canalogistix@gmail.com<br/>
    © {timezone.now().year} CanaLogistiX - Cana Group of Companies. All rights reserved.</i>
    '''
    
    story.append(Paragraph(footer_text, footer_style))
    
    # Build PDF
    doc.build(story)
    logger.info(f"Generated acknowledgement PDF for order {order.id}")
    
    return buffer


@csrf_exempt
@require_http_methods(["POST"])
def upload_signature_acknowledgement(request):
    """
    API endpoint to generate and upload customer signature acknowledgement PDF
    
    Expected POST parameters:
    - orderId: The delivery order ID
    - signature: Base64 encoded signature image blob
    
    Returns:
    - JSON response with success status and public URL of uploaded PDF
    """
    try:
        # Get parameters
        order_id = request.POST.get('orderId')
        signature_base64 = request.POST.get('signature')
        
        if not order_id or not signature_base64:
            return JsonResponse({
                'success': False,
                'error': 'orderId and signature are required'
            }, status=400)
        
        # Get order with related pharmacy and driver
        order = get_object_or_404(
            DeliveryOrder.objects.select_related('pharmacy', 'driver'),
            id=order_id
        )
        
        # Validate order status
        if order.status != 'inTransit':
            return JsonResponse({
                'success': False,
                'error': 'Order must be in transit status to generate acknowledgement'
            }, status=400)
        
        # Decode base64 signature image
        try:
            # Log what we received for debugging
            logger.info(f"Received signature data length: {len(signature_base64)}")
            logger.info(f"Signature starts with: {signature_base64[:50]}")
            
            # Remove data URL prefix if present (e.g., "data:image/png;base64,")
            if 'base64,' in signature_base64:
                signature_base64 = signature_base64.split('base64,')[1]
                logger.info(f"After removing prefix, length: {len(signature_base64)}")
            
            # Clean up the base64 string - remove whitespace and newlines
            signature_base64 = ''.join(signature_base64.split())
            
            # Add padding if needed (base64 strings must be divisible by 4)
            padding_needed = len(signature_base64) % 4
            if padding_needed:
                signature_base64 += '=' * (4 - padding_needed)
                logger.info(f"Added {4 - padding_needed} padding characters")
            
            # Decode base64
            try:
                signature_data = base64.b64decode(signature_base64, validate=True)
                logger.info(f"Successfully decoded {len(signature_data)} bytes")
            except Exception as decode_error:
                logger.error(f"Base64 decode error: {decode_error}")
                logger.error(f"Base64 string length: {len(signature_base64)}")
                logger.error(f"First 100 chars: {signature_base64[:100]}")
                logger.error(f"Last 100 chars: {signature_base64[-100:]}")
                return JsonResponse({
                    'success': False,
                    'error': f'Invalid base64 signature data: {str(decode_error)}'
                }, status=400)
            
            # Validate we got image data
            if len(signature_data) < 100:  # Arbitrary minimum size
                return JsonResponse({
                    'success': False,
                    'error': 'Signature data too small, please sign again'
                }, status=400)
            
            # Save signature temporarily
            temp_signature_path = f'/tmp/signature_{order_id}_{int(time.time())}.png'
            
            try:
                # Open image from bytes first to validate it
                img = PILImage.open(BytesIO(signature_data))
                
                # Convert RGBA to RGB with white background (if needed)
                if img.mode in ('RGBA', 'LA'):
                    background = PILImage.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'RGBA':
                        background.paste(img, mask=img.split()[3])  # Use alpha channel as mask
                    else:
                        background.paste(img, mask=img.split()[1])
                    img = background
                elif img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Save the processed image
                img.save(temp_signature_path, 'PNG')
                logger.info(f"Successfully saved signature image: {temp_signature_path}")
                
            except Exception as img_error:
                logger.error(f"Invalid signature image: {img_error}")
                logger.error(f"Image data starts with: {signature_data[:20]}")
                if os.path.exists(temp_signature_path):
                    os.remove(temp_signature_path)
                return JsonResponse({
                    'success': False,
                    'error': f'Invalid signature image format: {str(img_error)}'
                }, status=400)
            
        except Exception as e:
            logger.error(f"Error processing signature: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to process signature: {str(e)}'
            }, status=400)
        
        # Generate PDF
        try:
            pdf_buffer = generate_acknowledgement_pdf(order, temp_signature_path)
            pdf_buffer.seek(0)
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            # Clean up temp file
            if os.path.exists(temp_signature_path):
                os.remove(temp_signature_path)
            return JsonResponse({
                'success': False,
                'error': f'Failed to generate acknowledgement PDF: {str(e)}'
            }, status=500)
        
        # Upload to GCP
        try:
            # Initialize GCP client
            credentials = service_account.Credentials.from_service_account_file(
                settings.GCP_KEY_PATH
            )
            client = storage.Client(credentials=credentials)
            bucket = client.bucket(settings.GCP_BUCKET_NAME)
            
            # Build file path
            filename = f"order_{order.id}_pharmacy_{order.pharmacy.id}_{int(time.time())}.pdf"
            gcp_path = (
                f"{settings.GCP_INVOICE_FOLDER}/"
                f"{settings.GCP_CUSTOMER_PHARMACY_SIGNED_ACKNOWLEDGEMENTS}/"
                f"{filename}"
            )
            
            # Upload PDF
            blob = bucket.blob(gcp_path)
            blob.upload_from_file(
                pdf_buffer,
                content_type='application/pdf'
            )
            
            # Generate public URL
            public_url = f"https://storage.googleapis.com/{bucket.name}/{gcp_path}"
            
            # Save URL to database
            order.signature_ack_url = public_url
            order.save(update_fields=['signature_ack_url'])
            
            logger.info(f"Successfully uploaded acknowledgement PDF for order {order.id}")
            
            # Clean up temp signature file
            if os.path.exists(temp_signature_path):
                os.remove(temp_signature_path)
            
            return JsonResponse({
                'success': True,
                'order_id': order.id,
                'acknowledgement_url': public_url,
                'message': 'Acknowledgement PDF generated and uploaded successfully'
            })
            
        except Exception as e:
            logger.error(f"Error uploading to GCP: {e}")
            # Clean up temp file
            if os.path.exists(temp_signature_path):
                os.remove(temp_signature_path)
            return JsonResponse({
                'success': False,
                'error': f'Failed to upload PDF to cloud storage: {str(e)}'
            }, status=500)
        
    except Exception as e:
        logger.error(f"Unexpected error in upload_signature_acknowledgement: {e}")
        return JsonResponse({
            'success': False,
            'error': f'An unexpected error occurred: {str(e)}'
        }, status=500)

    
@csrf_exempt
@require_http_methods(["POST"])
def verify_customer_id(request):
    """
    API endpoint to mark ID verification as completed for an order

    Expected POST parameters:
    - orderId: The delivery order ID
    - driverId: The driver performing verification
    - verified: Boolean indicating verification status (ignored; we always set True)

    Returns:
    - JSON response with success status
    """
    try:
        order_id = request.POST.get('orderId')
        driver_id = request.POST.get('driverId')
        _ = request.POST.get('verified')  # keep input structure, but ignored

        if not order_id or not driver_id:
            return JsonResponse({
                'success': False,
                'error': 'orderId and driverId are required'
            }, status=400)

        # Get order and validate driver
        order = get_object_or_404(DeliveryOrder, id=order_id)

        if str(order.driver_id) != str(driver_id):
            return JsonResponse({
                'success': False,
                'error': 'Driver is not assigned to this order'
            }, status=403)

        # Validate order status - ID verification should happen during delivery
        if order.status not in ['inTransit', 'delivered']:
            return JsonResponse({
                'success': False,
                'error': 'ID verification can only be done during transit or delivery'
            }, status=400)

        # ✅ MAIN LOGIC: always set id_verified = True
        if not order.id_verified:
            order.id_verified = True
            order.save(update_fields=['id_verified', 'updated_at'])

        logger.info(f"ID verification set TRUE for order {order_id} by driver {driver_id}")

        return JsonResponse({
            'success': True,
            'order_id': order.id,
            'message': 'ID verification recorded successfully'
        })

    except Exception as e:
        logger.error(f"Unexpected error in verify_customer_id: {e}")
        return JsonResponse({
            'success': False,
            'error': f'An unexpected error occurred: {str(e)}'
        }, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_driver_cc_points(request, driver_id):
    try:
        # (Optional but recommended) Validate driver exists
        if not Driver.objects.filter(id=driver_id).exists():
            return JsonResponse({
                "success": False,
                "error": "Driver not found"
            }, status=404)

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
        })

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)