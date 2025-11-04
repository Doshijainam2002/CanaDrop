from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from CanaDrop_Interface.models import *
from django.utils.dateparse import parse_date
from django.conf import settings
import logging
import requests
from django.db import transaction, connection
from decimal import Decimal
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404
from django.conf import settings
from .models import Pharmacy, DeliveryOrder, OrderImage, OrderTracking, Driver
import json
import logging
import os
from google.cloud import storage
from datetime import timedelta
from django.http import JsonResponse, HttpResponseBadRequest
import os
from datetime import timedelta
from decimal import Decimal
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from google.cloud import storage
import io
import pytz
from datetime import timedelta, date, datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ValidationError
import json
from django.conf import settings
from google.cloud import storage



# Add this for better error logging
logger = logging.getLogger(__name__)


def pharmacyLoginView(request):
    return render(request, 'pharmacyLogin.html')

def pharmacyRegisterView(request):
    return render(request, 'pharmacyRegister.html')

def pharmacyDashboardView(request):
    return render(request, 'pharmacyDashboard.html')

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
    return render(request, 'driverRegister.html')

def contactAdminView(request):
    return render(request, 'contactAdmin.html')

def landingView(request):
    return render(request, 'landingPage.html')


def pharmacyProfileView(request):
    return render(request, 'pharmacyProfile.html')


@csrf_exempt
def pharmacy_login_api(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Only POST method allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")
    except Exception as e:
        return JsonResponse({"success": False, "message": "Invalid JSON"}, status=400)
    
    if not email or not password:
        return JsonResponse({"success": False, "message": "Email and password required"}, status=400)
    
    try:
        pharmacy = Pharmacy.objects.get(email=email)
    except Pharmacy.DoesNotExist:
        return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)
    
    if pharmacy.check_password(password):
        return JsonResponse({"success": True, "id": pharmacy.id})
    else:
        return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)


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
            # print(f"Request data: {data}")

            pharmacy_id = data.get('pharmacyId')
            pickup_address = data.get('pickupAddress')
            pickup_city = data.get('pickupCity')
            pickup_day = data.get('pickupDay')
            drop_address = data.get('dropAddress')
            drop_city = data.get('dropCity')
            customer_name = data.get('customerName')  # <-- added

            # Validate required fields
            if not all([pharmacy_id, pickup_address, pickup_city, pickup_day, drop_address, drop_city]):
                # print("Validation failed: Missing required fields")
                return JsonResponse({"success": False, "error": "Missing required fields"}, status=400)

            # print(f"Fetching pharmacy with ID: {pharmacy_id}")
            pharmacy = Pharmacy.objects.get(id=pharmacy_id)
            # print(f"Pharmacy found: {pharmacy.name}")

            # Get distance directly - no separate address validation
            # print("Calculating distance...")
            distance_km, error = get_distance_km(pickup_address, pickup_city, drop_address, drop_city)
            if error:
                # print(f"Distance calculation failed: {error}")
                return JsonResponse({"success": False, "error": error}, status=400)
            # print(f"Distance calculated: {distance_km} km")

            # Determine rate based on distance
            rate_entry = DeliveryDistanceRate.objects.filter(
                min_distance_km__lte=distance_km
            ).order_by('min_distance_km').last()
            rate = rate_entry.rate if rate_entry else 0
            # print(f"Rate determined: {rate}")

            # Create the delivery order with status 'pending'
            # print("Creating DeliveryOrder...")
            create_kwargs = dict(
                pharmacy=pharmacy,
                pickup_address=pickup_address,
                pickup_city=pickup_city,
                pickup_day=parse_date(pickup_day),
                drop_address=drop_address,
                drop_city=drop_city,
                status='pending',  # Set initial status
                rate=rate
            )
            if customer_name:  # <-- only set if provided; otherwise model default applies
                create_kwargs["customer_name"] = customer_name

            order = DeliveryOrder.objects.create(**create_kwargs)
            
            # Force commit the order creation
            transaction.commit()
            # print(f"Order created and committed: ID={order.id}")
            
            # Verify order exists in database
            order_exists = DeliveryOrder.objects.filter(id=order.id).exists()
            # print(f"Order {order.id} exists in database: {order_exists}")
            
            if order_exists:
                # Create initial tracking entry using the function
                # print("Creating initial tracking entry...")
                tracking_result = create_order_tracking_entry(
                    order_id=order.id,
                    step='pending',
                    performed_by=f'Pharmacy: {pharmacy.name}',
                    note='Order created and pending driver acceptance'
                )
                
                if tracking_result["success"]:
                    # print(f"Tracking entry created successfully: {tracking_result}")
                    return JsonResponse({
                        "success": True,
                        "orderId": order.id,
                        "distance_km": distance_km,
                        "rate": str(rate),
                        "status": order.status,
                        "customerName": order.customer_name,  # <-- added to response
                        "tracking_id": tracking_result["tracking_id"],
                        "message": "Order and tracking created successfully"
                    })
                else:
                    # print(f"Tracking entry creation failed: {tracking_result['error']}")
                    # Return success for order but note tracking failure
                    return JsonResponse({
                        "success": True,
                        "orderId": order.id,
                        "distance_km": distance_km,
                        "rate": str(rate),
                        "status": order.status,
                        "customerName": order.customer_name,  # <-- added to response
                        "tracking_created": False,
                        "tracking_error": tracking_result["error"],
                        "message": "Order created successfully but tracking entry failed"
                    })
            else:
                # print("Order was not properly saved to database")
                return JsonResponse({
                    "success": False, 
                    "error": "Order creation failed - not saved to database"
                }, status=500)

        except Pharmacy.DoesNotExist:
            # print("Pharmacy not found")
            return JsonResponse({"success": False, "error": "Pharmacy not found"}, status=404)
        except Exception as e:
            # print(f"Error in create_delivery_order: {e}")
            import traceback
            traceback.print_exc()
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    # print("Invalid HTTP method")
    return JsonResponse({"success": False, "error": "Invalid HTTP method"}, status=405)



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


def get_pharmacy_details(request, pharmacy_id):
    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
        data = {
            "id": pharmacy.id,
            "name": pharmacy.name,
            "store_address": pharmacy.store_address,
            "city": pharmacy.city,
            "province": pharmacy.province,
            "postal_code": pharmacy.postal_code,
            "country": pharmacy.country,
            "phone_number": pharmacy.phone_number,
            "email": pharmacy.email,
            "created_at": pharmacy.created_at,
        }
        return JsonResponse({"success": True, "pharmacy": data}, status=200)

    except Pharmacy.DoesNotExist:
        return JsonResponse({"success": False, "message": "Pharmacy not found"}, status=404)


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
        orders = DeliveryOrder.objects.filter(pharmacy=pharmacy).prefetch_related(
            'tracking_entries',
            'images'
        ).order_by('-created_at')
        
        orders_data = []
        
        for order in orders:
            # Get tracking entries for timeline
            tracking_entries = list(order.tracking_entries.all().values(
                'step', 'performed_by', 'timestamp', 'note', 'image_url'
            ))
            
            # Convert timestamps to string for JSON serialization
            for entry in tracking_entries:
                entry['timestamp'] = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else None
            
            # Get images by stage
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
            
            # Count total images
            total_images = sum(len(images) for images in images_by_stage.values())
            
            # Calculate progress percentage based on status
            progress_map = {
                'pending': 25,
                'accepted': 50,
                'picked_up': 75,
                'delivered': 100,
                'cancelled': 0
            }
            
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
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': order.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'driver_id': order.driver.id if order.driver else None,
                # Fixed: Use first_name and last_name directly from Driver model
                'driver_name': order.driver.name if order.driver else None,
                'progress_percentage': progress_map.get(order.status, 0),
                'total_images': total_images,
                'timeline': tracking_entries,
                'images': images_by_stage
            }
            
            orders_data.append(order_data)
        
        response_data = {
            'success': True,
            'pharmacy_id': pharmacy.id,
            'pharmacy_name': pharmacy.name,
            'total_orders': len(orders_data),
            'orders': orders_data
        }
        
        return JsonResponse(response_data, encoder=DecimalEncoder, safe=False)
        
    except Pharmacy.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Pharmacy not found'
        }, status=404)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'An error occurred: {str(e)}'
        }, status=500)






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
            bucket = client.bucket('canadrop-bucket')
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


@csrf_exempt
def get_pending_orders(request):
    if request.method == "GET":
        # Fetch all pending orders ordered by created_at (oldest first)
        orders = DeliveryOrder.objects.filter(status="pending").order_by("created_at")

        # Prepare JSON data manually
        data = []
        for order in orders:
            data.append({
                "id": order.id,
                "pharmacy": order.pharmacy.name if order.pharmacy else None,
                "driver": order.driver.name if order.driver else None,
                "pickup_address": order.pickup_address,
                "pickup_city": order.pickup_city,
                "pickup_day": order.pickup_day.strftime("%Y-%m-%d"),
                "drop_address": order.drop_address,
                "drop_city": order.drop_city,
                "status": order.status,
                "rate": str(order.rate),
                "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": order.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

        return JsonResponse({"orders": data}, safe=False)

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
                "email": driver.email
            }, status=200)
        except Driver.DoesNotExist:
            return JsonResponse({"error": "Driver not found"}, status=404)

    return JsonResponse({"error": "Invalid request method"}, status=405)

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
        status__in=["accepted", "picked_up", "inTransit"]  # Include all active statuses
    ).select_related("pharmacy")

    orders = []
    for o in qs:
        # Calculate distance for each order
        distance_km = 0  # Default value
        if o.pickup_address and o.pickup_city and o.drop_address and o.drop_city:
            calculated_distance, error = get_distance_km(
                o.pickup_address, 
                o.pickup_city, 
                o.drop_address, 
                o.drop_city
            )
            if calculated_distance is not None:
                distance_km = calculated_distance
        
        orders.append({
            "id": o.id,
            "pharmacy_id": o.pharmacy_id,
            "pharmacy_name": getattr(o.pharmacy, "name", None),
            "driver_id": o.driver_id,
            "pickup_address": o.pickup_address,
            "pickup_city": o.pickup_city,
            "pickup_day": o.pickup_day.isoformat() if o.pickup_day else None,
            "drop_address": o.drop_address,
            "drop_city": o.drop_city,
            "status": o.status,
            "rate": float(o.rate) if isinstance(o.rate, Decimal) else o.rate,
            "distance_km": round(distance_km, 2),  # Round to 2 decimal places
            "created_at": o.created_at.isoformat() if o.created_at else None,
            "updated_at": o.updated_at.isoformat() if o.updated_at else None,
        })

    return JsonResponse({"orders": orders})

# @csrf_exempt
# def driver_pickup_proof(request):
#     if request.method != "POST":
#         return HttpResponseBadRequest("Only POST method allowed")

#     driver_id = request.POST.get("driverId")
#     order_id = request.POST.get("orderId")
#     pharmacy_id = request.POST.get("pharmacyId")
#     image_file = request.FILES.get("image")

#     if not (driver_id and order_id and pharmacy_id and image_file):
#         return HttpResponseBadRequest("driverId, orderId, pharmacyId and image are required")

#     try:
#         # fetch objects
#         driver = get_object_or_404(Driver, id=driver_id)
#         order = get_object_or_404(DeliveryOrder, id=order_id)
#         pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

#         # step 1: update order status to inTransit
#         order.status = "inTransit"
#         order.save()

#         # step 2: upload image to GCP
#         key_path = settings.GCP_KEY_PATH
#         bucket_name = "canadrop-bucket"  # Fixed bucket name

#         client = storage.Client.from_service_account_json(key_path)
#         bucket = client.bucket(bucket_name)

#         safe_pharmacy_name = pharmacy.name.replace(" ", "_")
#         filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_driverpickup.jpg"
#         blob = bucket.blob(f"Proof/{filename}")
#         blob.upload_from_file(image_file, content_type=image_file.content_type)

#         # generate signed URL valid for 7 days
#         signed_url = blob.generate_signed_url(expiration=timedelta(days=7), method="GET")

#         # step 3a: create order tracking entry
#         note_text = f"Driver Pickup Image Uploaded : {driver_id}_{order_id}_{pharmacy_id}_DriverPickup"
#         performed_by = f"Driver: {driver.name}"
#         OrderTracking.objects.create(
#             order=order,
#             driver=driver,
#             pharmacy=pharmacy,
#             step="inTransit",
#             performed_by=performed_by,
#             note=note_text,
#             image_url=signed_url,
#         )

#         # step 3b: create order image entry
#         OrderImage.objects.create(
#             order=order,
#             image_url=signed_url,
#             stage="pickup"
#         )

#         return JsonResponse({
#             "success": True,
#             "message": "Pickup proof uploaded successfully",
#             "image_url": signed_url
#         })

#     except Exception as e:
#         return JsonResponse({
#             "success": False,
#             "message": f"Error uploading pickup proof: {str(e)}"
#         }, status=500)


# @csrf_exempt
# def driver_delivery_proof(request):
#     if request.method != "POST":
#         return HttpResponseBadRequest("Only POST method allowed")

#     driver_id = request.POST.get("driverId")
#     order_id = request.POST.get("orderId")
#     pharmacy_id = request.POST.get("pharmacyId")
#     image_file = request.FILES.get("image")

#     if not (driver_id and order_id and pharmacy_id and image_file):
#         return HttpResponseBadRequest("driverId, orderId, pharmacyId and image are required")

#     try:
#         # fetch objects
#         driver = get_object_or_404(Driver, id=driver_id)
#         order = get_object_or_404(DeliveryOrder, id=order_id)
#         pharmacy = get_object_or_404(Pharmacy, id=pharmacy_id)

#         # step 1: update order status to delivered
#         order.status = "delivered"
#         order.save()

#         # step 2: upload image to GCP
#         key_path = settings.GCP_KEY_PATH
#         bucket_name = "canadrop-bucket"  # Fixed bucket name

#         client = storage.Client.from_service_account_json(key_path)
#         bucket = client.bucket(bucket_name)

#         safe_pharmacy_name = pharmacy.name.replace(" ", "_")
#         filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_delivered.jpg"
#         blob = bucket.blob(f"Proof/{filename}")
#         blob.upload_from_file(image_file, content_type=image_file.content_type)

#         # signed URL (valid for 7 days)
#         signed_url = blob.generate_signed_url(expiration=timedelta(days=7), method="GET")

#         # step 3a: order tracking entry
#         note_text = f"Driver Delivery Image Uploaded : {driver_id}_{order_id}_{pharmacy_id}_Delivered"
#         performed_by = f"Driver: {driver.name}"
#         OrderTracking.objects.create(
#             order=order,
#             driver=driver,
#             pharmacy=pharmacy,
#             step="delivered",
#             performed_by=performed_by,
#             note=note_text,
#             image_url=signed_url,
#         )

#         # step 3b: order image entry
#         OrderImage.objects.create(
#             order=order,
#             image_url=signed_url,
#             stage="delivered"
#         )

#         return JsonResponse({
#             "success": True,
#             "message": "Delivery proof uploaded successfully",
#             "image_url": signed_url
#         })

#     except Exception as e:
#         return JsonResponse({
#             "success": False,
#             "message": f"Error uploading delivery proof: {str(e)}"
#         }, status=500)


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
        bucket_name = "canadrop-bucket"  # Fixed bucket name

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
        order.save()

        # step 2: upload image to GCP
        key_path = settings.GCP_KEY_PATH
        bucket_name = "canadrop-bucket"  # Fixed bucket name

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



import os
import json
import logging
from datetime import timedelta
from decimal import Decimal
from io import BytesIO

from django.conf import settings
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from google.cloud import storage
from google.oauth2 import service_account
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from .models import DeliveryOrder, Pharmacy, Invoice

# Configure logger
logger = logging.getLogger(__name__)

# GCP Storage configuration
GCP_BUCKET_NAME = "canadrop-bucket"
GCP_FOLDER_NAME = "PharmacyInvoices"


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
    bucket = client.bucket("canadrop-bucket")
    blob = bucket.blob(f"PharmacyInvoices/{filename}")
    pdf_buffer.seek(0)
    blob.upload_from_file(pdf_buffer, content_type="application/pdf")
    # bucket is public → public URL ok; or use signed URL if you prefer
    return f"https://storage.googleapis.com/canadrop-bucket/PharmacyInvoices/{filename}"


def generate_invoice_pdf(invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount):
    """Generate PDF invoice and upload to GCP bucket"""
    
    # Create PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, leftMargin=0.5*inch, rightMargin=0.5*inch)
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Modern styling
    company_style = ParagraphStyle(
        'CompanyName',
        parent=styles['Normal'],
        fontSize=18,
        spaceAfter=5,
        alignment=TA_CENTER,
        textColor=colors.Color(0.2, 0.2, 0.2),  # Dark grey
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CompanySubtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.Color(0.4, 0.4, 0.4)  # Medium grey
    )
    
    address_style = ParagraphStyle(
        'CompanyAddress',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=25,
        alignment=TA_CENTER,
        textColor=colors.Color(0.3, 0.3, 0.3)
    )
    
    section_header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontSize=14,
        spaceAfter=10,
        fontName='Helvetica-Bold',
        textColor=colors.Color(0.1, 0.1, 0.1)
    )
    
    # Build PDF content
    content = []
    
    # Logo - Reduced width
    logo_path = os.path.join(settings.BASE_DIR, "Logo", "Website_Logo_No_Background.png")

    try:
        logo = Image(logo_path, width=2*inch, height=1*inch)  # Reduced from 3x1.5 to 2x1
        logo.hAlign = 'CENTER'
        content.append(logo)
        content.append(Spacer(1, 15))
    except:
        # Fallback if logo not found
        logger.warning(f"Logo not found at path: {logo_path}, using text fallback")
        content.append(Paragraph("CanaDrop", company_style))
    
    # Company info with modern styling
    content.append(Paragraph("Cana Group of Companies", subtitle_style))
    content.append(Paragraph("12 - 147 Fairway Road North<br/>Kitchener, N2A 2N3, Ontario, Canada", address_style))
    
    # Modern invoice header with reduced size and better alignment
    content.append(Spacer(1, 10))
    
    # Reduced invoice title size to match section headers
    invoice_title = Paragraph("INVOICE", ParagraphStyle(
        'InvoiceTitle',
        parent=styles['Normal'],
        fontSize=14,  # Reduced from 32 to 14 to match section headers
        fontName='Helvetica-Bold',
        textColor=colors.Color(0.1, 0.1, 0.1),
        alignment=TA_LEFT,
        spaceAfter=15
    ))
    content.append(invoice_title)
    
    # Better aligned invoice details table
    invoice_info_data = [
        [
            Paragraph("<b>Invoice Number:</b>", styles['Normal']),
            Paragraph(f"#{invoice.id:06d}", ParagraphStyle('InvoiceNum', parent=styles['Normal'], fontSize=12, fontName='Helvetica-Bold'))
        ],
        [
            Paragraph("<b>Issue Date:</b>", styles['Normal']),
            Paragraph(invoice.created_at.strftime('%B %d, %Y'), styles['Normal'])
        ],
        [
            Paragraph("<b>Due Date:</b>", styles['Normal']),
            Paragraph(invoice.due_date.strftime('%B %d, %Y'), styles['Normal'])
        ],
        [
            Paragraph("<b>Billing Period:</b>", styles['Normal']),
            Paragraph(f'{invoice.start_date.strftime("%B %d, %Y")} - {invoice.end_date.strftime("%B %d, %Y")}', styles['Normal'])
        ]
    ]
    
    # Adjusted column widths for better left alignment
    invoice_info_table = Table(invoice_info_data, colWidths=[1.5*inch, 4*inch])
    invoice_info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),  # Left align labels
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),  # Left align values
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),  # Slightly reduced padding
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),  # Remove left padding for better alignment
    ]))
    content.append(invoice_info_table)
    content.append(Spacer(1, 30))
    
    # Bill To section with modern card styling
    content.append(Paragraph("BILL TO", section_header_style))
    
    # Pharmacy info with simpler styling (avoid complex border properties)
    pharmacy_info = f"""
    <b>{pharmacy.name}</b><br/>
    {pharmacy.store_address}<br/>
    {pharmacy.city}, {pharmacy.province} {pharmacy.postal_code}<br/>
    {pharmacy.country}<br/><br/>
    <b>Email:</b> {pharmacy.email}<br/>
    <b>Phone:</b> {pharmacy.phone_number}
    """
    
    pharmacy_para = Paragraph(pharmacy_info, ParagraphStyle(
        'PharmacyInfo',
        parent=styles['Normal'],
        fontSize=10,
        leftIndent=15,
        rightIndent=15,
        spaceBefore=10,
        spaceAfter=10,
        backColor=colors.Color(0.98, 0.98, 0.98)
    ))
    content.append(pharmacy_para)
    content.append(Spacer(1, 30))
    
    # Modern orders table
    content.append(Paragraph("DELIVERY ORDERS", section_header_style))
    content.append(Spacer(1, 10))
    
    # Modern table headers with better styling
    table_data = [['Order ID', 'Date', 'Pickup Location', 'Delivery Location', 'Amount']]
    
    # Add order rows with better formatting
    for order in orders_data:
        table_data.append([
            f"#{order['order_id']}",
            order['pickup_day'],
            f"{order['pickup_address']}\n{order['pickup_city']}",
            f"{order['drop_address']}\n{order['drop_city']}",
            f"${order['rate']:.2f}"
        ])
    
    # Create modern orders table
    orders_table = Table(table_data, colWidths=[0.9*inch, 1*inch, 2.3*inch, 2.3*inch, 0.9*inch])
    
    # Build table style dynamically based on actual number of rows
    table_style_commands = [
        # Header styling
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.3, 0.5)),  # Modern blue
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        
        # Data rows styling
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (-1, 0), (-1, -1), 'RIGHT'),  # Amount column right aligned
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        
        # Border styling
        ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.7, 0.7, 0.7)),
        ('LINEBELOW', (0, 0), (-1, 0), 2, colors.Color(0.2, 0.3, 0.5)),
        
        # Padding
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]
    
    # Add alternating row colors only for existing rows
    num_data_rows = len(table_data) - 1  # Exclude header row
    for i in range(1, num_data_rows + 1):  # Start from row 1 (after header)
        if i % 2 == 0:  # Even rows (2, 4, 6, etc.)
            table_style_commands.append(('BACKGROUND', (0, i), (-1, i), colors.Color(0.95, 0.95, 0.95)))
    
    orders_table.setStyle(TableStyle(table_style_commands))
    content.append(orders_table)
    content.append(Spacer(1, 30))
    
    # Modern summary section
    content.append(Paragraph("INVOICE SUMMARY", section_header_style))
    content.append(Spacer(1, 10))
    
    # Summary table with modern styling
    summary_data = [
        ['Subtotal:', f'${subtotal:.2f}'],
        ['HST (13%):', f'${hst_amount:.2f}'],
        ['', ''],  # Empty row for spacing
        ['Total Amount:', f'${total_amount:.2f}']
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1.2*inch], hAlign='RIGHT')
    summary_table.setStyle(TableStyle([
        # Regular rows
        ('FONTNAME', (0, 0), (-1, 2), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, 2), 12),
        ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
        
        # Total row styling
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, -1), (-1, -1), 16),
        ('BACKGROUND', (0, -1), (-1, -1), colors.Color(0.2, 0.3, 0.5)),
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.white),
        
        # Borders and spacing
        ('LINEABOVE', (0, -1), (-1, -1), 2, colors.Color(0.2, 0.3, 0.5)),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15),
        
        # Hide the empty spacing row
        ('LINEABOVE', (0, 2), (-1, 2), 0, colors.white),
        ('LINEBELOW', (0, 2), (-1, 2), 0, colors.white),
    ]))
    content.append(summary_table)
    
    # Modern footer
    content.append(Spacer(1, 40))
    footer_text = "Thank you for choosing CanaDrop for your delivery needs!"
    footer_para = Paragraph(footer_text, ParagraphStyle(
        'ModernFooter',
        parent=styles['Normal'],
        fontSize=12,
        alignment=TA_CENTER,
        textColor=colors.Color(0.3, 0.3, 0.3),
        fontName='Helvetica-Oblique'
    ))
    content.append(footer_para)
    
    # Build PDF
    doc.build(content)
    
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

    invoices_list = []
    week_start = earliest

    # === CHANGE 1: include current partial week ===
    # Previously: while week_start + timedelta(days=6) <= latest:
    while week_start <= latest:
        week_end = min(week_start + timedelta(days=6), latest)

        # Filter orders only in this week and delivered
        week_orders = orders_qs.filter(
            created_at__date__gte=week_start,
            created_at__date__lte=week_end
        )
        total_orders = week_orders.count()

        if total_orders > 0:
            logger.debug(f"Processing week {week_start} to {week_end} with {total_orders} orders")

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
                    filename = f"{pharmacy.id}_{pharmacy_name_clean}_{start_date_str}_{end_date_str}.pdf"

                    # === CHANGE 2: require GCS upload to succeed; NO local fallback ===
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







import stripe
import json
import logging
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404
from .models import Invoice, Pharmacy

# Set up logging
logger = logging.getLogger(__name__)

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
    logger.info("=== STRIPE WEBHOOK RECEIVED ===")
    
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
    
    logger.info(f"Webhook payload length: {len(payload)}")
    logger.info(f"Stripe signature header: {sig_header}")
    logger.info(f"Endpoint secret configured: {bool(endpoint_secret)}")
    
    if not endpoint_secret:
        logger.error("Webhook secret not configured in settings")
        return HttpResponse('Webhook secret not configured', status=400)
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        logger.info(f"Webhook event constructed successfully: {event['type']}")
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        return HttpResponse('Invalid payload', status=400)
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        return HttpResponse('Invalid signature', status=400)
    
    # Handle the event
    logger.info(f"Processing webhook event type: {event['type']}")
    
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        logger.info(f"Checkout session completed: {session['id']}")
        logger.info(f"Session metadata: {session.get('metadata', {})}")
        
        # Get invoice details from metadata
        invoice_id = session.get('metadata', {}).get('invoice_id')
        pharmacy_id = session.get('metadata', {}).get('pharmacy_id')
        payment_intent_id = session.get('payment_intent')
        
        logger.info(f"Invoice ID from metadata: {invoice_id}")
        logger.info(f"Pharmacy ID from metadata: {pharmacy_id}")
        logger.info(f"Payment intent ID: {payment_intent_id}")
        
        if invoice_id and pharmacy_id:
            try:
                # Convert to integers
                invoice_id = int(invoice_id)
                pharmacy_id = int(pharmacy_id)
                
                # Update invoice status to paid
                invoice = Invoice.objects.get(id=invoice_id, pharmacy_id=pharmacy_id)
                logger.info(f"Found invoice to update: {invoice}")
                logger.info(f"Current invoice status: {invoice.status}")
                
                invoice.status = 'paid'
                
                # Store the Stripe payment intent ID if the field exists
                if payment_intent_id:
                    if hasattr(invoice, 'stripe_payment_id'):
                        invoice.stripe_payment_id = payment_intent_id
                        logger.info(f"Stored payment intent ID: {payment_intent_id}")
                    elif hasattr(invoice, 'payment_id'):
                        invoice.payment_id = payment_intent_id
                        logger.info(f"Stored payment ID: {payment_intent_id}")
                    else:
                        logger.warning("No payment ID field found in Invoice model")
                
                invoice.save()
                logger.info(f"Invoice {invoice_id} successfully marked as paid")
                
            except Invoice.DoesNotExist:
                logger.error(f"Invoice {invoice_id} not found for pharmacy {pharmacy_id}")
                return HttpResponse('Invoice not found', status=404)
            except ValueError as e:
                logger.error(f"Error converting metadata to integers: {e}")
                return HttpResponse('Invalid metadata format', status=400)
            except Exception as e:
                logger.error(f"Error updating invoice {invoice_id}: {str(e)}")
                return HttpResponse('Error updating invoice', status=500)
        else:
            logger.error("Missing invoice_id or pharmacy_id in session metadata")
            return HttpResponse('Missing required metadata', status=400)
    
    elif event['type'] == 'payment_intent.succeeded':
        # Handle successful payment intent if needed
        payment_intent = event['data']['object']
        logger.info(f"Payment intent {payment_intent['id']} succeeded")
    
    else:
        logger.info(f"Unhandled event type: {event['type']}")
    
    logger.info("=== STRIPE WEBHOOK PROCESSED SUCCESSFULLY ===")
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



import os
import pytz
from datetime import date, timedelta
from decimal import Decimal
from io import BytesIO

from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from google.cloud import storage
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from .models import DeliveryOrder, Driver, DriverInvoice

# Default user timezone (from your conversation context)
USER_TZ = pytz.timezone("America/Toronto")

# GCP Storage configuration
GCP_BUCKET_NAME = "canadrop-bucket"
GCP_FOLDER_NAME = "DriverSummary"
GCP_KEY_PATH = settings.GCP_KEY_PATH


def _start_of_week(d: date):
    """Return the Monday of the week containing date d."""
    return d - timedelta(days=d.weekday())


def _end_of_week(d: date):
    """Return the Sunday of the week containing date d."""
    return _start_of_week(d) + timedelta(days=6)


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
            # print(f"GCP key file not found at: {GCP_KEY_PATH}")
            return None
        
        # Initialize client with service account key
        client = storage.Client.from_service_account_json(GCP_KEY_PATH)
        return client
    except Exception as e:
        # print(f"Error initializing GCP client: {str(e)}")
        return None


def _upload_to_gcp(pdf_buffer, filename):
    """Upload PDF to GCP Storage and return the public URL."""
    try:
        client = _get_gcp_client()
        if not client:
            # print("Failed to initialize GCP client")
            return None
            
        bucket = client.bucket(GCP_BUCKET_NAME)
        blob_name = f"{GCP_FOLDER_NAME}/{filename}"
        blob = bucket.blob(blob_name)
        
        pdf_buffer.seek(0)
        blob.upload_from_file(pdf_buffer, content_type='application/pdf')
        
        # For uniform bucket-level access, construct the public URL directly
        # Format: https://storage.googleapis.com/bucket-name/object-name
        public_url = f"https://storage.googleapis.com/{GCP_BUCKET_NAME}/{blob_name}"
        
        # print(f"Successfully uploaded {filename} to GCP Storage")
        # print(f"Public URL: {public_url}")
        return public_url
    except Exception as e:
        # print(f"Error uploading to GCP: {str(e)}")
        return None


def _generate_invoice_pdf(driver, week_data, orders):
    """Generate comprehensive PDF invoice for a driver's weekly summary."""
    buffer = BytesIO()
    
    # Create the PDF document with better margins
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50,
                          topMargin=50, bottomMargin=50)
    
    # Container for the 'Flowable' objects
    story = []
    
    # Define comprehensive styles
    styles = getSampleStyleSheet()
    
    # Main title style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1a365d'),
        fontName='Helvetica-Bold'
    )
    
    # Subtitle style
    subtitle_style = ParagraphStyle(
        'SubTitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=25,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#2d3748'),
        fontName='Helvetica'
    )
    
    # Section heading style
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=18,
        spaceAfter=15,
        spaceBefore=20,
        textColor=colors.HexColor('#1a365d'),
        fontName='Helvetica-Bold',
        borderWidth=0,
        borderColor=colors.HexColor('#e2e8f0'),
        borderPadding=5
    )
    
    # Normal text style
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=8,
        leading=14,
        fontName='Helvetica'
    )
    
    # Info box style
    info_style = ParagraphStyle(
        'InfoBox',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=12,
        leading=14,
        leftIndent=20,
        rightIndent=20,
        fontName='Helvetica',
        backColor=colors.HexColor('#f7fafc'),
        borderWidth=1,
        borderColor=colors.HexColor('#e2e8f0'),
        borderPadding=10
    )
    
    # Add company header with logo
    try:
        logo_path = os.path.join(settings.BASE_DIR, "Logo", "Website_Logo_No_Background.png")

        if os.path.exists(logo_path):
            # Create header table with logo and company info
            logo = Image(logo_path, width=2.5*inch, height=1.8*inch)
            
            company_info = Paragraph("""
            <b>CanaDrop Delivery Services</b><br/>
            By CGC - Cana Group of Companies<br/>
            Email: help.canadrop@gmail.com<br/>
            
            """, normal_style)
            
            header_data = [[logo, company_info]]
            header_table = Table(header_data, colWidths=[3*inch, 4*inch])
            header_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(header_table)
            story.append(Spacer(1, 30))
    except Exception as e:
        # print(f"Logo not found: {str(e)}")
        # Fallback header without logo
        story.append(Paragraph("CanaDrop Delivery Services", title_style))
        story.append(Paragraph("Professional Pharmacy Delivery Solutions", subtitle_style))
    
    # Main document title
    story.append(Paragraph("DRIVER PAYMENT INVOICE", title_style))
    story.append(Spacer(1, 30))
    
    # Invoice metadata in a professional layout
    from datetime import datetime
    current_date = datetime.now().strftime("%B %d, %Y")
    invoice_number = f"INV-{driver.id}-{week_data['payment_period']['start_date'].replace('-', '')}"
    
    metadata_data = [
        ['Invoice Number:', invoice_number, 'Issue Date:', current_date],
        ['Driver ID:', f"#{driver.id}", 'Payment Due:', week_data['due_date']],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 2*inch])
    metadata_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 25))
    
    # Driver Information Section
    story.append(Paragraph("DRIVER INFORMATION", heading_style))
    
    driver_details = f"""
    <b>Full Name:</b> {driver.name}<br/>
    <b>Email Address:</b> {driver.email}<br/>
    <b>Driver ID:</b> #{driver.id}<br/>
    <b>Status:</b> Active Driver
    """
    story.append(Paragraph(driver_details, info_style))
    story.append(Spacer(1, 20))
    
    # Payment Period Section
    story.append(Paragraph("PAYMENT PERIOD DETAILS", heading_style))
    
    start_date = week_data['payment_period']['start_date']
    end_date = week_data['payment_period']['end_date']
    period_details = f"""
    <b>Service Period:</b> {start_date} to {end_date}<br/>
    <b>Total Service Days:</b> 7 days<br/>
    <b>Payment Status:</b> {week_data['status'].title()}<br/>
    <b>Payment Due Date:</b> {week_data['due_date']}<br/>
    <b>Processing Date:</b> {current_date}
    """
    story.append(Paragraph(period_details, info_style))
    story.append(Spacer(1, 25))
    
    # Financial Summary Section
    story.append(Paragraph("PAYMENT BREAKDOWN", heading_style))
    
    # Calculate detailed financial information
    gross_amount = sum(Decimal(str(order.rate or 0)) for order in orders)
    commission_rate = Decimal('0.15')
    commission_amount = gross_amount * commission_rate
    net_amount = gross_amount - commission_amount
    
    # Create detailed summary table
    summary_data = [
        ['Description', 'Amount (CAD)'],
        ['Total Deliveries Completed', f"{week_data['total_orders']} orders"],
        ['Gross Revenue', f"${gross_amount:.2f}"],
        ['Platform Commission (15%)', f"-${commission_amount:.2f}"],
        ['', ''],  # Separator row
        ['NET PAYMENT DUE', f"${net_amount:.2f}"],
    ]
    
    summary_table = Table(summary_data, colWidths=[4*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        
        # Regular rows
        ('FONTNAME', (0, 1), (-1, -2), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -2), 11),
        ('ALIGN', (0, 1), (0, -2), 'LEFT'),
        ('ALIGN', (1, 1), (1, -2), 'RIGHT'),
        
        # Total row (last row)
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e6fffa')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, -1), (-1, -1), 14),
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.HexColor('#1a365d')),
        ('ALIGN', (0, -1), (0, -1), 'LEFT'),
        ('ALIGN', (1, -1), (1, -1), 'RIGHT'),
        
        # Borders and padding
        ('GRID', (0, 0), (-1, -2), 1, colors.HexColor('#e2e8f0')),
        ('BOX', (0, -1), (-1, -1), 2, colors.HexColor('#1a365d')),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        
        # Hide separator row borders
        ('LINEBELOW', (0, 3), (-1, 3), 0, colors.white),
        ('LINEABOVE', (0, 4), (-1, 4), 0, colors.white),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 30))
    
    # Detailed Order Breakdown
    if orders:
        story.append(Paragraph("DETAILED ORDER BREAKDOWN", heading_style))
        
        # Create comprehensive order table
        order_data = [['Order #', 'Date', 'Pickup Location', 'Delivery Location', 'Status', 'Rate (CAD)']]
        
        total_distance = 0  # You might want to add this to your model
        for i, order in enumerate(orders, 1):
            delivery_date = _ensure_local(order.updated_at).strftime('%m/%d/%Y') if order.updated_at else 'N/A'
            pickup_location = f"{order.pickup_city}" if order.pickup_city else 'N/A'
            delivery_location = getattr(order, 'drop_city', None) or getattr(order, 'dropoff_city', None) or 'N/A'
            
            order_data.append([
                f"#{order.id}",
                delivery_date,
                pickup_location,
                delivery_location,
                order.status.title(),
                f"${order.rate or 0:.2f}"
            ])
        
        # Create styled order table
        order_table = Table(order_data, colWidths=[0.8*inch, 1*inch, 1.8*inch, 1.8*inch, 1*inch, 1*inch])
        order_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Data rows
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Order numbers
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),  # Dates
            ('ALIGN', (2, 1), (3, -1), 'LEFT'),    # Locations
            ('ALIGN', (4, 1), (4, -1), 'CENTER'),  # Status
            ('ALIGN', (5, 1), (5, -1), 'RIGHT'),   # Rates
            
            # Styling
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(order_table)
        story.append(Spacer(1, 25))
    
    # Payment Terms and Conditions
    story.append(Paragraph("PAYMENT TERMS & CONDITIONS", heading_style))
    
    terms_text = """
    <b>Payment Schedule:</b> Weekly payments are processed every Monday for the previous week's completed deliveries.<br/><br/>
    <b>Commission Structure:</b> CanaDrop retains 15% of gross delivery fees to cover platform costs, insurance, and support services.<br/><br/>
    <b>Payment Method:</b> Payments are made via direct deposit to the driver's registered bank account.<br/><br/>
    <b>Dispute Resolution:</b> Any payment disputes must be reported within 7 days of invoice issuance.<br/><br/>
    <b>Tax Responsibility:</b> As an independent contractor, you are responsible for reporting this income on your tax returns.
    """
    story.append(Paragraph(terms_text, normal_style))
    story.append(Spacer(1, 25))
    
    # Contact Information
    story.append(Paragraph("SUPPORT & CONTACT", heading_style))
    
    contact_text = """
    For questions about this payment summary or any delivery-related inquiries:<br/><br/>
    <b>Email:</b> help.canadrop@gmail.com<br/>
    <b>Business Hours:</b> Monday - Friday, 9:00 AM - 6:00 PM EST<br/>
    """
    story.append(Paragraph(contact_text, info_style))
    story.append(Spacer(1, 30))
    
    # Professional Footer
    footer_text = f"""
    <i>This invoice was automatically generated on {current_date} by CanaDrop's payment processing system.<br/>
    Invoice #{invoice_number} | Driver Payment Summary | Confidential Document<br/>
    © 2025 CanaDrop Delivery Services. All rights reserved.</i>
    """
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#6b7280'),
        spaceAfter=0
    )
    story.append(Paragraph(footer_text, footer_style))
    
    # Build the PDF
    doc.build(story)
    
    return buffer


@csrf_exempt
def driver_invoice_weeks(request):
    """
    GET param: driverId
    Returns weekly invoice buckets for delivered orders for that driver.
    Now includes PDF generation and GCP storage using service account key.
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
        for o in week_orders:
            rate = o.rate if o.rate is not None else Decimal("0.00")
            if not isinstance(rate, Decimal):
                rate = Decimal(str(rate))
            total_amount += (rate * Decimal("0.85"))

        due_date = wend + timedelta(days=7)

        # Check if DriverInvoice already exists for this period
        existing_invoice = DriverInvoice.objects.filter(
            driver=driver,
            start_date=wstart,
            end_date=wend
        ).first()

        pdf_url = None
        if existing_invoice:
            # Use existing PDF URL if available
            pdf_url = existing_invoice.pdf_url
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
                filename = f"{driver.id}_{driver.name.replace(' ', '_')}_{wstart.isoformat()}_{wend.isoformat()}.pdf"
                
                # Upload to GCP
                pdf_url = _upload_to_gcp(pdf_buffer, filename)
                
                if pdf_url:
                    new_invoice.pdf_url = pdf_url
                    new_invoice.save()
                    # print(f"Successfully created invoice with PDF URL: {pdf_url}")
                else:
                    print("Failed to upload PDF to GCP, continuing without PDF URL")
                    
                    
            except Exception as e:
                print(f"Error generating/uploading PDF: {str(e)}")

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
            "status": "generated",
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
        
        # Add pharmacy or driver reference
        if pharmacy_id:
            try:
                pharmacy = Pharmacy.objects.get(id=pharmacy_id)
                contact_data['pharmacy'] = pharmacy
            except Pharmacy.DoesNotExist:
                return JsonResponse({'error': 'Invalid pharmacy ID'}, status=400)
        
        if driver_id:
            try:
                driver = Driver.objects.get(id=driver_id)
                contact_data['driver'] = driver
            except Driver.DoesNotExist:
                return JsonResponse({'error': 'Invalid driver ID'}, status=400)
        
        # Create record
        contact = ContactAdmin.objects.create(**contact_data)
        
        return JsonResponse({
            'success': True,
            'message': 'Your message has been sent successfully. We will get back to you soon.',
            'contact_id': contact.id
        })
        
    except Exception as e:
        return JsonResponse({
            'error': 'An error occurred while processing your request. Please try again.'
        }, status=500)




import json
import random

from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMessage
from django.core.signing import dumps, loads, BadSignature, SignatureExpired
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password

from .models import Pharmacy  # your model

# ---- Simple config ----
OTP_TTL_SECONDS = 10 * 60          # 10 minutes
VERIFY_TOKEN_TTL_SECONDS = 15 * 60 # token usable for 15 minutes
SIGNING_SALT = "canadrop-otp-verify"
EMAIL_FROM = getattr(settings, "GMAIL_ADDRESS", None)  # e.g. "help.canadrop@gmail.com"

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

def _send_html_email(subject: str, to_email: str, html: str, text_fallback: str = " "):
    msg = EmailMessage(subject=subject, body=html, from_email=EMAIL_FROM, to=[to_email])
    msg.content_subtype = "html"
    msg.send(fail_silently=False)

# ---------- Views ----------
from datetime import datetime
import random
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpRequest

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
    brand_primary = "#0d9488"       # teal-600
    brand_primary_dark = "#0f766e"  # teal-700
    brand_accent = "#06b6d4"        # cyan-500

    # Modern, responsive-friendly HTML (works in Gmail/Outlook/Apple Mail)
    html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>CanaDrop Verification Code</title>
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
      Your CanaDrop verification code. Expires in {OTP_TTL_SECONDS//60} minute(s).
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
                      <img src="https://i.postimg.cc/c4jt62GM/Website-Logo-No-Background.png"
                           alt="CanaDrop"
                           width="40" height="40"
                           style="display:block;border:0;outline:none;text-decoration:none;">
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
                  Your CanaDrop verification code
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
            © {datetime.utcnow().year} CanaDrop. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    subject = f"Your CanaDrop code • Expires in {OTP_TTL_SECONDS // 60} min"
    text = f"Your CanaDrop verification code is: {otp}\nThis code expires in {OTP_TTL_SECONDS//60} minute(s).\nIf you didn’t request it, you can ignore this message."

    try:
        _send_html_email(subject, email, html, text)
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

    # --- Light-theme confirmation email (matches send_otp style) ---
    try:
        # Brand colors (bluish green family)
        brand_primary = "#0d9488"       # teal-600
        brand_primary_dark = "#0f766e"  # teal-700

        logo_url = "https://i.postimg.cc/c4jt62GM/Website-Logo-No-Background.png"
        changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")
        site_url = getattr(settings, "SITE_URL", "").rstrip("/")
        reset_link = f"{site_url}/forgotPassword/" if site_url else "/forgotPassword/"

        html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed Successfully • CanaDrop</title>
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
      Your CanaDrop password was changed on {changed_at}.
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
                           alt="CanaDrop"
                           width="40" height="40"
                           style="display:block;border:0;outline:none;text-decoration:none;">
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
                  Your CanaDrop account password was changed on
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
            © {timezone.now().year} CanaDrop. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "CanaDrop — Password Changed Successfully\n\n"
            f"Timestamp: {changed_at}\n\n"
            "If you did not make this change, please reset your password immediately:\n"
            f"{reset_link}\n"
        )

        _send_html_email(
            subject="Your CanaDrop password was changed",
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
        brand_primary = "#0d9488"        # teal-600
        brand_primary_dark = "#0f766e"   # teal-700
        bg_dark = "#0b1220"              # page background
        card_dark = "#0f172a"            # card background
        border_dark = "#1f2937"          # borders
        text_light = "#e5e7eb"           # primary text
        text_muted = "#94a3b8"           # muted text

        logo_url = "https://i.postimg.cc/c4jt62GM/Website-Logo-No-Background.png"
        changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")

        html = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed • CanaDrop Driver</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background:{bg_dark};">
    <!-- Preheader (hidden) -->
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Your CanaDrop driver password was changed on {changed_at}.
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
                      <img src="{logo_url}" alt="CanaDrop" width="40" height="40" style="display:block;border:0;outline:none;text-decoration:none;">
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
                  Your CanaDrop <strong style="color:{text_light};">driver</strong> account password was changed on
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
            © {timezone.now().year} CanaDrop. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "CanaDrop — Driver Password Changed Successfully\n\n"
            f"Timestamp: {changed_at}\n\n"
            "If you did not make this change, please reset your password immediately."
        )

        _send_html_email(
            subject="Your CanaDrop driver password was changed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Driver password-change email failed to send")

    return _ok("Driver password changed successfully.")





from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

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
        brand_primary = "#0d9488"       # teal-600
        brand_primary_dark = "#0f766e"  # teal-700
        brand_accent = "#06b6d4"        # cyan-500
        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")
        logo_url = "https://i.postimg.cc/c4jt62GM/Website-Logo-No-Background.png"

        html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to CanaDrop • Pharmacy Registration</title>
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
      Registration confirmed — welcome to CanaDrop and the Cana Family by CGC.
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
                      <img src="{logo_url}" alt="CanaDrop" width="40" height="40" style="display:block;border:0;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Welcome to CanaDrop
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
                  Thanks for registering with <strong>CanaDrop</strong> and joining the <strong>Cana Family by CGC</strong>.
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
                  Questions or need a hand? Just reply to this email—our team is happy to help.
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
            © {timezone.now().year} CanaDrop. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "Welcome to CanaDrop and the Cana Family by CGC!\n\n"
            f"Hi {name or 'there'}, your pharmacy registration is confirmed.\n"
            "• Live order tracking with photo proof\n"
            "• Weekly invoices and transparent earnings\n"
            "• Secure handover and delivery confirmations\n\n"
            "Questions? Just reply to this email.\n"
        )

        _send_html_email(
            subject="Welcome to CanaDrop • Pharmacy Registration Confirmed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send pharmacy registration email")

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
        brand_primary = "#0d9488"       # teal-600
        bg_dark = "#0b1220"
        card_dark = "#0f172a"
        border_dark = "#1f2937"
        text_light = "#e5e7eb"
        text_muted = "#94a3b8"
        logo_url = "https://i.postimg.cc/c4jt62GM/Website-Logo-No-Background.png"
        now_str = timezone.now().strftime("%b %d, %Y %H:%M %Z")

        html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Welcome to CanaDrop • Driver Registration</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background:{bg_dark};">
    <div style="display:none;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">
      Registration confirmed — welcome to CanaDrop and the Cana Family by CGC.
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
                      <img src="{logo_url}" alt="CanaDrop" width="40" height="40" style="display:block;border:0;">
                    </td>
                    <td align="right" style="font:600 16px/1.2 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:#e6fffb;">
                      Welcome to CanaDrop
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:28px 24px 6px;">
                <h1 style="margin:0 0 10px;font:800 24px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_light};">
                  Hey {name or "driver"}, you’re in! 🚚
                </h1>
                <p style="margin:0 0 16px;font:400 14px/1.7 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;color:{text_muted};">
                  Welcome to <strong style="color:{text_light};">CanaDrop</strong> and the <strong style="color:{text_light};">Cana Family by CGC</strong>.
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
            © {timezone.now().year} CanaDrop. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""
        text = (
            "Welcome to CanaDrop and the Cana Family by CGC!\n\n"
            f"Hey {name or 'driver'}, your driver registration is confirmed.\n"
            "• Photo-verified delivery steps\n"
            "• Clear delivery details and navigation\n"
            "• Weekly earnings summaries\n\n"
            "Questions? Just reply to this email.\n"
        )

        _send_html_email(
            subject="Welcome to CanaDrop • Driver Registration Confirmed",
            to_email=email,
            html=html,
            text_fallback=text,
        )
    except Exception:
        logger.exception("Failed to send driver registration email")

    return _ok("Driver registration successful.", id=driver.id, email=driver.email)



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET


@csrf_exempt
@require_GET
def get_pharmacy_details(request, pharmacy_id):
    """
    GET API: Returns all information of a pharmacy by pharmacyId.
    Example: /api/getPharmacyDetails/1/
    """
    try:
        pharmacy = Pharmacy.objects.get(id=pharmacy_id)
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
            },
        }
        return JsonResponse(data, status=200)
    except Pharmacy.DoesNotExist:
        return JsonResponse({"success": False, "error": "Pharmacy not found."}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
import json
from .models import Pharmacy


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
    brand_primary = "#0d9488"       # teal-600
    brand_primary_dark = "#0f766e"  # teal-700
    logo_url = "https://i.postimg.cc/c4jt62GM/Website-Logo-No-Background.png"
    changed_at = timezone.now().strftime("%b %d, %Y %H:%M %Z")

    html_content = f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Password Changed Successfully • CanaDrop</title>
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
      Your CanaDrop password was changed on {changed_at}.
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
                      <img src="{logo_url}" alt="CanaDrop" width="40" height="40"
                           style="display:block;border:0;outline:none;text-decoration:none;">
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
                  Your CanaDrop account password was changed on
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
            © {timezone.now().year} CanaDrop. All rights reserved.
          </p>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    text_content = (
        f"CanaDrop — Password Changed Successfully\n\n"
        f"Your password was changed on {changed_at}.\n\n"
        "If you did not perform this change, please reset your password immediately.\n\n"
        "CanaDrop Support\n"
    )

    subject = "Your CanaDrop Password Was Changed Successfully"
    from_email = settings.DEFAULT_FROM_EMAIL
    msg = EmailMultiAlternatives(subject, text_content, from_email, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send(fail_silently=True)




from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from .models import Pharmacy
import json


@csrf_exempt
@require_POST
def edit_pharmacy_profile(request):
    """
    POST API to update pharmacy profile information.
    It accepts pharmacyId and any combination of editable fields.
    Example Body:
    {
        "pharmacyId": 1,
        "name": "New Pharmacy Name",
        "store_address": "123 New Street",
        "city": "Waterloo",
        "province": "Ontario",
        "postal_code": "N2L 3E2",
        "country": "Canada",
        "phone_number": "9876543210",
        "email": "newemail@pharmacy.com"
    }
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

        # Allowed editable fields
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

        # Track updated fields
        updated_fields = []

        for field in editable_fields:
            if field in data and getattr(pharmacy, field) != data[field]:
                setattr(pharmacy, field, data[field])
                updated_fields.append(field)

        if not updated_fields:
            return JsonResponse({"success": False, "message": "No fields were changed."}, status=200)

        # Save only changed fields
        pharmacy.save(update_fields=updated_fields)

        return JsonResponse({
            "success": True,
            "message": f"Profile updated successfully.",
            "updated_fields": updated_fields
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)




# import json
# import googlemaps
# from django.http import JsonResponse
# from django.conf import settings
# from django.views.decorators.csrf import csrf_exempt
# from django.views.decorators.http import require_http_methods
# from ortools.constraint_solver import pywrapcp, routing_enums_pb2
# import logging
# from collections import defaultdict
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from django.core.cache import cache
# import hashlib

# logger = logging.getLogger(__name__)


# def get_cache_key(addresses):
#     """Generate cache key for distance matrix"""
#     addr_str = "|".join(sorted(addresses))
#     return f"dist_matrix_{hashlib.md5(addr_str.encode()).hexdigest()}"


# def get_distance_matrix_parallel(gmaps, addresses):
#     """
#     Fetch distance matrix with parallel batch requests and caching.
#     This significantly reduces API call time.
#     """
#     # Check cache first
#     cache_key = get_cache_key(addresses)
#     cached_matrix = cache.get(cache_key)
#     if cached_matrix:
#         logger.info(f"Using cached distance matrix for {len(addresses)} addresses")
#         return cached_matrix
    
#     n = len(addresses)
#     distance_matrix = [[999999 for _ in range(n)] for _ in range(n)]
#     batch_size = 10
    
#     def fetch_batch(i, j):
#         """Fetch a single batch"""
#         origins = addresses[i:min(i + batch_size, n)]
#         destinations = addresses[j:min(j + batch_size, n)]
        
#         try:
#             matrix = gmaps.distance_matrix(
#                 origins,
#                 destinations,
#                 mode="driving",
#                 units="metric",
#                 departure_time="now"  # Use real-time traffic
#             )
            
#             if matrix.get("status") != "OK":
#                 logger.error(f"Batch request failed: {matrix.get('status')}")
#                 return None
            
#             return (i, j, matrix)
            
#         except Exception as e:
#             logger.error(f"Error fetching batch ({i}, {j}): {str(e)}")
#             return None
    
#     # Create batch requests
#     batch_requests = []
#     for i in range(0, n, batch_size):
#         for j in range(0, n, batch_size):
#             batch_requests.append((i, j))
    
#     logger.info(f"Fetching {len(batch_requests)} batches in parallel for {n} addresses")
    
#     # Execute batches in parallel (max 5 concurrent to respect API limits)
#     with ThreadPoolExecutor(max_workers=5) as executor:
#         futures = {executor.submit(fetch_batch, i, j): (i, j) for i, j in batch_requests}
        
#         for future in as_completed(futures):
#             result = future.result()
#             if result:
#                 i, j, matrix = result
                
#                 # Fill in the distance matrix
#                 for row_idx, row in enumerate(matrix.get("rows", [])):
#                     for col_idx, elem in enumerate(row.get("elements", [])):
#                         actual_i = i + row_idx
#                         actual_j = j + col_idx
                        
#                         if elem.get("status") == "OK":
#                             distance_value = elem.get("distance", {}).get("value", 999999)
#                             distance_matrix[actual_i][actual_j] = distance_value
#                         else:
#                             distance_matrix[actual_i][actual_j] = 999999
    
#     # Cache for 1 hour
#     cache.set(cache_key, distance_matrix, 3600)
#     logger.info(f"Distance matrix cached successfully")
    
#     return distance_matrix


# def solve_single_date_group(date_key, date_deliveries, start_location, gmaps):
#     """
#     Solve optimization for a single date group.
#     Extracted to allow parallel processing if needed.
#     """
#     logger.info(f"Optimizing {len(date_deliveries)} deliveries for date: {date_key}")
    
#     # Build addresses list
#     addresses = [start_location]
#     pickup_indices = []
#     drop_indices = []
#     order_ids = []
    
#     for d in date_deliveries:
#         pickup_indices.append(len(addresses))
#         addresses.append(d["pickup_address"])
#         drop_indices.append(len(addresses))
#         addresses.append(d["dropoff_address"])
#         order_ids.append(d.get("order_id"))
    
#     n = len(addresses)
#     logger.info(f"Date {date_key}: {n} addresses (1 start + {len(pickup_indices)} pickups + {len(drop_indices)} dropoffs)")

#     # Get distance matrix with caching and parallelization
#     try:
#         distance_matrix = get_distance_matrix_parallel(gmaps, addresses)
#     except Exception as e:
#         logger.error(f"Distance matrix error for date {date_key}: {str(e)}")
#         raise

#     # Validate matrix
#     if len(distance_matrix) != n or any(len(row) != n for row in distance_matrix):
#         raise ValueError("Invalid distance matrix dimensions")

#     # Initialize OR-Tools Routing Model
#     manager = pywrapcp.RoutingIndexManager(n, 1, 0)
#     routing = pywrapcp.RoutingModel(manager)

#     def distance_callback(from_index, to_index):
#         f = manager.IndexToNode(from_index)
#         t = manager.IndexToNode(to_index)
#         return distance_matrix[f][t]

#     transit_cb = routing.RegisterTransitCallback(distance_callback)
#     routing.SetArcCostEvaluatorOfAllVehicles(transit_cb)

#     # Add Distance dimension
#     routing.AddDimension(
#         transit_cb,
#         0,
#         10000000,
#         True,
#         "Distance"
#     )
#     distance_dim = routing.GetDimensionOrDie("Distance")

#     # Add pickup-delivery constraints
#     for idx, (p, d) in enumerate(zip(pickup_indices, drop_indices)):
#         pickup_idx = manager.NodeToIndex(p)
#         delivery_idx = manager.NodeToIndex(d)
        
#         routing.AddPickupAndDelivery(pickup_idx, delivery_idx)
#         routing.solver().Add(
#             routing.VehicleVar(pickup_idx) == routing.VehicleVar(delivery_idx)
#         )
#         routing.solver().Add(
#             distance_dim.CumulVar(pickup_idx) <= distance_dim.CumulVar(delivery_idx)
#         )

#     logger.info(f"Added {len(pickup_indices)} pickup-delivery constraints for date {date_key}")

#     # Optimized solver parameters - faster but still good quality
#     search_params = pywrapcp.DefaultRoutingSearchParameters()
#     search_params.first_solution_strategy = routing_enums_pb2.FirstSolutionStrategy.PATH_CHEAPEST_ARC
#     search_params.local_search_metaheuristic = routing_enums_pb2.LocalSearchMetaheuristic.GUIDED_LOCAL_SEARCH
    
#     # Adaptive timeout based on problem size
#     timeout = min(15 + (n // 10), 30)  # 15-30 seconds based on size
#     search_params.time_limit.seconds = timeout
    
#     # Limit solution attempts for faster response
#     search_params.solution_limit = 50

#     logger.info(f"Solving route for date {date_key} with {timeout}s timeout...")
#     solution = routing.SolveWithParameters(search_params)
    
#     if not solution:
#         raise ValueError(f"No feasible route found for date {date_key}")

#     logger.info(f"Solution found for date {date_key}! Building route...")

#     # Build metadata map
#     node_meta = {0: {"kind": "start", "order_id": None, "date": date_key}}
#     addr_i = 1
#     for idx, order_id in enumerate(order_ids):
#         node_meta[addr_i] = {"kind": "pickup", "order_id": order_id, "date": date_key}
#         addr_i += 1
#         node_meta[addr_i] = {"kind": "dropoff", "order_id": order_id, "date": date_key}
#         addr_i += 1

#     # Extract optimized route
#     index = routing.Start(0)
#     date_stops = []
#     date_distance = 0
#     last_address = None
    
#     while not routing.IsEnd(index):
#         node = manager.IndexToNode(index)
#         meta = node_meta.get(node, {"kind": "unknown", "order_id": None, "date": date_key})
#         next_index = solution.Value(routing.NextVar(index))
#         next_node = manager.IndexToNode(next_index)
        
#         if node < len(distance_matrix) and next_node < len(distance_matrix[node]):
#             leg_distance = distance_matrix[node][next_node]
#         else:
#             leg_distance = 0
        
#         date_distance += leg_distance
#         last_address = addresses[node]
        
#         date_stops.append({
#             "kind": meta["kind"],
#             "address": addresses[node],
#             "order_id": meta["order_id"],
#             "date": meta["date"],
#             "leg_distance_km": round(leg_distance / 1000, 2)
#         })
        
#         index = next_index
    
#     logger.info(f"✓ Date {date_key}: {len(date_stops)} stops, {round(date_distance/1000, 2)}km")
    
#     return {
#         "stops": date_stops,
#         "distance": date_distance,
#         "last_address": last_address
#     }


# @csrf_exempt
# @require_http_methods(["POST"])
# def optimize_route_api(request):
#     """
#     Optimized delivery route API with:
#     - Parallel distance matrix fetching
#     - Distance matrix caching
#     - Adaptive solver timeouts
#     - Better error handling
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

#         logger.info(f"✓✓ FULL ROUTE OPTIMIZED: {len(all_stops)} total stops, {round(total_distance/1000, 2)}km across {len(deliveries_by_date)} dates")

#         return JsonResponse({
#             "success": True,
#             "stops": all_stops,
#             "total_distance_km": round(total_distance / 1000, 2),
#             "dates_optimized": len(deliveries_by_date)
#         })

#     except json.JSONDecodeError as e:
#         logger.error(f"JSON decode error: {str(e)}")
#         return JsonResponse({"error": "Invalid JSON payload", "success": False}, status=400)
#     except Exception as e:
#         logger.exception(f"Unexpected error in route optimization: {str(e)}")
#         return JsonResponse({"error": f"Internal server error: {str(e)}", "success": False}, status=500)


import json
import googlemaps
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from ortools.constraint_solver import pywrapcp, routing_enums_pb2
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.cache import cache
import hashlib

logger = logging.getLogger(__name__)


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








