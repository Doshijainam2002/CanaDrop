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

# Add this for better error logging
logger = logging.getLogger(__name__)


def pharmacyLoginView(request):
    return render(request, 'pharmacyLogin.html')

def pharmacyDashboardView(request):
    return render(request, 'pharmacyDashboard.html')

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
        print("Address validation failed:", e)
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
        print("Distance calculation failed:", e)
        return 0, "Failed to calculate distance"



def create_order_tracking_entry(order_id, step='pending', performed_by=None, note=None, image_url=None):
    """
    Function to create tracking entries for orders
    """
    try:
        print(f"Creating tracking entry for order ID: {order_id}")
        
        # Get the order object
        order = DeliveryOrder.objects.get(id=order_id)
        print(f"Order found: {order}")
        
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
        print(f"Tracking entry created and committed: ID={tracking_entry.id}")
        
        # Verify it was saved
        tracking_count = OrderTracking.objects.filter(order=order).count()
        print(f"Total tracking entries for order {order.id}: {tracking_count}")
        
        return {
            "success": True,
            "tracking_id": tracking_entry.id,
            "step": tracking_entry.step,
            "performed_by": tracking_entry.performed_by,
            "timestamp": tracking_entry.timestamp.isoformat(),
            "message": "Tracking entry created successfully"
        }
        
    except DeliveryOrder.DoesNotExist:
        print(f"Order with ID {order_id} not found")
        return {
            "success": False,
            "error": f"Order with ID {order_id} not found"
        }
    except Exception as e:
        print(f"Error creating tracking entry: {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "error": str(e)
        }


@csrf_exempt
def create_delivery_order(request):
    """
    Main function to create delivery order and initial tracking entry
    """
    print("Entered create_delivery_order API")
    
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            print(f"Request data: {data}")

            pharmacy_id = data.get('pharmacyId')
            pickup_address = data.get('pickupAddress')
            pickup_city = data.get('pickupCity')
            pickup_day = data.get('pickupDay')
            drop_address = data.get('dropAddress')
            drop_city = data.get('dropCity')

            # Validate required fields
            if not all([pharmacy_id, pickup_address, pickup_city, pickup_day, drop_address, drop_city]):
                print("Validation failed: Missing required fields")
                return JsonResponse({"success": False, "error": "Missing required fields"}, status=400)

            print(f"Fetching pharmacy with ID: {pharmacy_id}")
            pharmacy = Pharmacy.objects.get(id=pharmacy_id)
            print(f"Pharmacy found: {pharmacy.name}")

            # Get distance dynamically and validate addresses
            print("Calculating distance...")
            distance_km, error = get_distance_km(pickup_address, pickup_city, drop_address, drop_city)
            if error:
                print(f"Address validation failed: {error}")
                return JsonResponse({"success": False, "error": error}, status=400)
            print(f"Distance calculated: {distance_km} km")

            # Determine rate based on distance
            rate_entry = DeliveryDistanceRate.objects.filter(
                min_distance_km__lte=distance_km
            ).order_by('min_distance_km').last()
            rate = rate_entry.rate if rate_entry else 0
            print(f"Rate determined: {rate}")

            # Create the delivery order with status 'pending'
            print("Creating DeliveryOrder...")
            order = DeliveryOrder.objects.create(
                pharmacy=pharmacy,
                pickup_address=pickup_address,
                pickup_city=pickup_city,
                pickup_day=parse_date(pickup_day),
                drop_address=drop_address,
                drop_city=drop_city,
                status='pending',  # Set initial status
                rate=rate
            )
            
            # Force commit the order creation
            transaction.commit()
            print(f"Order created and committed: ID={order.id}")
            
            # Verify order exists in database
            order_exists = DeliveryOrder.objects.filter(id=order.id).exists()
            print(f"Order {order.id} exists in database: {order_exists}")
            
            if order_exists:
                # Create initial tracking entry using the function
                print("Creating initial tracking entry...")
                tracking_result = create_order_tracking_entry(
                    order_id=order.id,
                    step='pending',
                    performed_by=f'Pharmacy: {pharmacy.name}',
                    note='Order created and pending driver acceptance'
                )
                
                if tracking_result["success"]:
                    print(f"Tracking entry created successfully: {tracking_result}")
                    return JsonResponse({
                        "success": True,
                        "orderId": order.id,
                        "distance_km": distance_km,
                        "rate": str(rate),
                        "status": order.status,
                        "tracking_id": tracking_result["tracking_id"],
                        "message": "Order and tracking created successfully"
                    })
                else:
                    print(f"Tracking entry creation failed: {tracking_result['error']}")
                    # Return success for order but note tracking failure
                    return JsonResponse({
                        "success": True,
                        "orderId": order.id,
                        "distance_km": distance_km,
                        "rate": str(rate),
                        "status": order.status,
                        "tracking_created": False,
                        "tracking_error": tracking_result["error"],
                        "message": "Order created successfully but tracking entry failed"
                    })
            else:
                print("Order was not properly saved to database")
                return JsonResponse({
                    "success": False, 
                    "error": "Order creation failed - not saved to database"
                }, status=500)

        except Pharmacy.DoesNotExist:
            print("Pharmacy not found")
            return JsonResponse({"success": False, "error": "Pharmacy not found"}, status=404)
        except Exception as e:
            print(f"Error in create_delivery_order: {e}")
            import traceback
            traceback.print_exc()
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    print("Invalid HTTP method")
    return JsonResponse({"success": False, "error": "Invalid HTTP method"}, status=405)


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
        print("Address validation failed:", e)
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
        print("Distance calculation failed:", e)
        return 0, "Failed to calculate distance"




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

            # Get distance dynamically and validate addresses
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
                "rate": rate
            })

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=500)

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
            
            # Fetch orders only for this pharmacy
            orders = DeliveryOrder.objects.filter(pharmacy=pharmacy).values(
                "id",
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
            from datetime import timedelta
            
            logger.info("Initializing Google Cloud Storage client...")
            
            # Define the path to your GCP service account key file
            gcp_key_path = "/Users/jainamdoshi/Desktop/Projects/CanaDrop/CanaDrop/gcp_key.json"
            
            # Check if the key file exists
            if not os.path.exists(gcp_key_path):
                logger.error(f"GCP key file not found at: {gcp_key_path}")
                return JsonResponse({
                    'success': False,
                    'error': 'GCP service account key file not found'
                }, status=500)
            
            # Create credentials from the key file
            credentials = service_account.Credentials.from_service_account_file(gcp_key_path)
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
            
            # Generate signed URL (valid for 7 days)
            signed_url = blob.generate_signed_url(
                expiration=timedelta(days=7),
                method='GET'
            )
            logger.info("Signed URL generated successfully")
            
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
                image_url=signed_url,
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
                image_url=signed_url
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
                'image_url': signed_url,
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
        key_path = "/Users/jainamdoshi/Desktop/Projects/CanaDrop/CanaDrop/gcp_key.json"
        bucket_name = "canadrop-bucket"  # Fixed bucket name

        client = storage.Client.from_service_account_json(key_path)
        bucket = client.bucket(bucket_name)

        safe_pharmacy_name = pharmacy.name.replace(" ", "_")
        filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_driverpickup.jpg"
        blob = bucket.blob(f"Proof/{filename}")
        blob.upload_from_file(image_file, content_type=image_file.content_type)

        # generate signed URL valid for 7 days
        signed_url = blob.generate_signed_url(expiration=timedelta(days=7), method="GET")

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
            image_url=signed_url,
        )

        # step 3b: create order image entry
        OrderImage.objects.create(
            order=order,
            image_url=signed_url,
            stage="pickup"
        )

        return JsonResponse({
            "success": True,
            "message": "Pickup proof uploaded successfully",
            "image_url": signed_url
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
        key_path = "/Users/jainamdoshi/Desktop/Projects/CanaDrop/CanaDrop/gcp_key.json"
        bucket_name = "canadrop-bucket"  # Fixed bucket name

        client = storage.Client.from_service_account_json(key_path)
        bucket = client.bucket(bucket_name)

        safe_pharmacy_name = pharmacy.name.replace(" ", "_")
        filename = f"{driver_id}_{order_id}_{safe_pharmacy_name}_delivered.jpg"
        blob = bucket.blob(f"Proof/{filename}")
        blob.upload_from_file(image_file, content_type=image_file.content_type)

        # signed URL (valid for 7 days)
        signed_url = blob.generate_signed_url(expiration=timedelta(days=7), method="GET")

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
            image_url=signed_url,
        )

        # step 3b: order image entry
        OrderImage.objects.create(
            order=order,
            image_url=signed_url,
            stage="delivered"
        )

        return JsonResponse({
            "success": True,
            "message": "Delivery proof uploaded successfully",
            "image_url": signed_url
        })

    except Exception as e:
        return JsonResponse({
            "success": False,
            "message": f"Error uploading delivery proof: {str(e)}"
        }, status=500)


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
import io


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

    # only delivered orders for this pharmacy
    orders_qs = DeliveryOrder.objects.filter(pharmacy_id=pharmacy_id, status="delivered").order_by("created_at")

    if not orders_qs.exists():
        return JsonResponse({"message": "No delivered orders for this pharmacy yet", "invoices": []})

    earliest = orders_qs.first().created_at.date()
    latest = orders_qs.last().created_at.date()

    invoices_list = []
    week_start = earliest

    while week_start + timedelta(days=6) <= latest:
        week_end = week_start + timedelta(days=6)

        # filter orders only in this week and delivered
        week_orders = orders_qs.filter(created_at__date__gte=week_start, created_at__date__lte=week_end)
        total_orders = week_orders.count()
        
        if total_orders > 0:
            # Calculate subtotal, HST, and final total
            subtotal = sum([Decimal(str(o.rate)) for o in week_orders])
            hst_rate = Decimal('0.13')  # 13% HST
            hst_amount = subtotal * hst_rate
            total_amount_with_hst = subtotal + hst_amount

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

            # Update existing invoice if needed
            if not created:
                invoice.total_orders = total_orders
                invoice.total_amount = total_amount_with_hst
                invoice.save()

            # Get order details for this week
            orders_data = []
            for order in week_orders:
                orders_data.append({
                    "order_id": order.id,
                    "pickup_address": order.pickup_address,
                    "pickup_city": order.pickup_city,
                    "drop_address": order.drop_address,
                    "drop_city": order.drop_city,
                    "pickup_day": order.pickup_day.strftime('%Y-%m-%d'),
                    "rate": float(order.rate),
                    "created_at": order.created_at.strftime('%Y-%m-%d %H:%M'),
                    "driver": order.driver.name if order.driver else "N/A"
                })

            # Generate PDF
            pdf_url = generate_invoice_pdf(invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount_with_hst)
            
            # Update invoice with PDF URL
            invoice.pdf_url = pdf_url
            invoice.save()

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
                "pdf_url": invoice.pdf_url,
                "orders": orders_data
            })

        # move to next week
        week_start += timedelta(days=7)

    return JsonResponse({"invoices": invoices_list})


def generate_invoice_pdf(invoice, pharmacy, orders_data, subtotal, hst_amount, total_amount):
    """Generate PDF invoice and return the URL"""
    
    # Create PDF buffer
    buffer = io.BytesIO()
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
    
    # Logo - Large and centered
    logo_path = "/Users/jainamdoshi/Desktop/Projects/CanaDrop/CanaDrop/Logo/Website_Logo_No_Background.png"
    try:
        logo = Image(logo_path, width=3*inch, height=1.5*inch)  # Large logo
        logo.hAlign = 'CENTER'
        content.append(logo)
        content.append(Spacer(1, 15))
    except:
        # Fallback if logo not found
        content.append(Paragraph("CanaDrop", company_style))
    
    # Company info with modern styling
    content.append(Paragraph("Cana Group of Companies", subtitle_style))
    content.append(Paragraph("12 - 147 Fairway Road North<br/>Kitchener, N2A 2N3, Ontario, Canada", address_style))
    
    # Modern invoice header with card-like styling
    content.append(Spacer(1, 10))
    
    # Modern invoice header with better layout
    invoice_title = Paragraph("INVOICE", ParagraphStyle(
        'InvoiceTitle',
        parent=styles['Normal'],
        fontSize=32,
        fontName='Helvetica-Bold',
        textColor=colors.Color(0.1, 0.1, 0.1),
        alignment=TA_LEFT,
        spaceAfter=15
    ))
    content.append(invoice_title)
    
    # Two-column layout for invoice details
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
    
    invoice_info_table = Table(invoice_info_data, colWidths=[2.2*inch, 3.5*inch])
    invoice_info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
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
    buffer.seek(0)
    
    # Save PDF file
    filename = f"invoice_{invoice.id}_{pharmacy.name.replace(' ', '_')}.pdf"
    file_path = f"invoices/{filename}"
    
    # Save to media storage
    saved_path = default_storage.save(file_path, ContentFile(buffer.getvalue()))
    
    # Return the URL
    if hasattr(settings, 'MEDIA_URL') and settings.MEDIA_URL:
        return f"{settings.MEDIA_URL}{saved_path}"
    else:
        return f"/media/{saved_path}"


