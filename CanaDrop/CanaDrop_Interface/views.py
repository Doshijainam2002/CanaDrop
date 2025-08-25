from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from CanaDrop_Interface.models import *
from django.utils.dateparse import parse_date
from django.conf import settings
import logging
import requests

def pharmacyLoginView(request):
    return render(request, 'pharmacyLogin.html')

def pharmacyDashboardView(request):
    return render(request, 'pharmacyDashboard.html')

def pharmacyOrdersView(request):
    return render(request, 'pharmacyOrders.html')

def pharmacyInvoicesView(request):
    return render(request, 'pharmacyInvoices.html')

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


@csrf_exempt
def create_delivery_order(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            pharmacy_id = data.get('pharmacyId')
            pickup_address = data.get('pickupAddress')
            pickup_city = data.get('pickupCity')
            pickup_day = data.get('pickupDay')
            drop_address = data.get('dropAddress')
            drop_city = data.get('dropCity')

            # Validate required fields
            if not all([pharmacy_id, pickup_address, pickup_city, pickup_day, drop_address, drop_city]):
                return JsonResponse({"success": False, "error": "Missing required fields"}, status=400)

            pharmacy = Pharmacy.objects.get(id=pharmacy_id)

            # Get distance dynamically and validate addresses
            distance_km, error = get_distance_km(pickup_address, pickup_city, drop_address, drop_city)
            if error:
                return JsonResponse({"success": False, "error": error}, status=400)

            # Determine rate based on distance
            rate_entry = DeliveryDistanceRate.objects.filter(
                min_distance_km__lte=distance_km
            ).order_by('min_distance_km').last()
            rate = rate_entry.rate if rate_entry else 0

            # Create the order
            order = DeliveryOrder.objects.create(
                pharmacy=pharmacy,
                pickup_address=pickup_address,
                pickup_city=pickup_city,
                pickup_day=parse_date(pickup_day),
                drop_address=drop_address,
                drop_city=drop_city,
                rate=rate
            )

            return JsonResponse({
                "success": True,
                "orderId": order.id,
                "distance_km": distance_km,
                "rate": rate
            })

        except Pharmacy.DoesNotExist:
            return JsonResponse({"success": False, "error": "Pharmacy not found"}, status=404)
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=500)

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
def create_delivery_order(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            pharmacy_id = data.get('pharmacyId')
            pickup_address = data.get('pickupAddress')
            pickup_city = data.get('pickupCity')
            pickup_day = data.get('pickupDay')
            drop_address = data.get('dropAddress')
            drop_city = data.get('dropCity')

            # Validate required fields
            if not all([pharmacy_id, pickup_address, pickup_city, pickup_day, drop_address, drop_city]):
                return JsonResponse({"success": False, "error": "Missing required fields"}, status=400)

            pharmacy = Pharmacy.objects.get(id=pharmacy_id)

            # Get distance dynamically and validate addresses
            distance_km, error = get_distance_km(pickup_address, pickup_city, drop_address, drop_city)
            if error:
                return JsonResponse({"success": False, "error": error}, status=400)

            # Determine rate based on distance
            rate_entry = DeliveryDistanceRate.objects.filter(
                min_distance_km__lte=distance_km
            ).order_by('min_distance_km').last()
            rate = rate_entry.rate if rate_entry else 0

            # Create the order
            order = DeliveryOrder.objects.create(
                pharmacy=pharmacy,
                pickup_address=pickup_address,
                pickup_city=pickup_city,
                pickup_day=parse_date(pickup_day),
                drop_address=drop_address,
                drop_city=drop_city,
                rate=rate
            )

            return JsonResponse({
                "success": True,
                "orderId": order.id,
                "distance_km": distance_km,
                "rate": rate
            })

        except Pharmacy.DoesNotExist:
            return JsonResponse({"success": False, "error": "Pharmacy not found"}, status=404)
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    return JsonResponse({"success": False, "error": "Invalid HTTP method"}, status=405)


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