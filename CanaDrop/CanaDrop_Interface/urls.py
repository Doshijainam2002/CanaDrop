from django.urls import path
from . import views  # make sure the import works

urlpatterns = [
    path('pharmacyLogin/', views.pharmacyLoginView, name='PharmacyLoginPage'),  
    path('pharmacyDashboard/', views.pharmacyDashboardView, name="PharmacyDashboardPage"),
    path('pharmacyOrders/', views.pharmacyOrdersView, name="PharmacyOrdersPage"),
    path('pharmacyInvoices/', views.pharmacyInvoicesView, name="PharmacyInvoicesPage"),
    path('api/pharmacy/login/', views.pharmacy_login_api, name='pharmacy-login-api'),
    path('api/createDeliveryOrder/', views.create_delivery_order, name='create_delivery_order'),
    path("api/get-delivery-rate/", views.get_delivery_rate, name="get_delivery_rate"),
    path("pharmacy/<int:pharmacy_id>/", views.get_pharmacy_details, name="get_pharmacy_details"),
    path("pharmacy/<int:pharmacy_id>/orders/", views.get_pharmacy_orders, name="get_pharmacy_orders"),
    path('api/pharmacy/<int:pharmacy_id>/orders/', views.pharmacy_orders_api, name='pharmacy_orders_api'),
    path('api/upload-handover-image/', views.upload_handover_image_api, name='upload_handover_image'),

]
