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
    path('pharmacyForgotPassword/', views.pharmacyForgotPasswordView, name="PharmacyForgotPasswordPage"),


    path('driverLogin/', views.driverLoginView, name='DriverLoginPage'),  
    path('api/driver/login/', views.driver_login, name='driver_login'),
    path('driverDashboard/', views.driverDashboardView, name="DriverDashboardPage"),
    path("api/orders/pending/", views.get_pending_orders, name="get_pending_orders"),
    path("api/orders/assign-driver/", views.assign_driver, name="assign_driver"),
    path("api/driver/details/", views.get_driver_details, name="get_driver_details"),
    path('driverAcceptedDeliveries/', views.driverAcceptedDeliveriesView, name="DriverAcceptedDeliveriesPage"),
    path("api/driver-orders/", views.driver_accepted_orders, name="driver_accepted_orders"),
    path("api/driver-pickup-proof/", views.driver_pickup_proof, name="driver_pickup_proof"),
    path("api/driver-delivery-proof/", views.driver_delivery_proof, name="driver_delivery_proof"),
    path("api/generate-weekly-invoices/", views.generate_weekly_invoices, name="generate_weekly_invoices"),
    path('api/create-checkout-session/', views.create_checkout_session, name='create_checkout_session'),
    path('webhooks/stripe/', views.stripe_webhook, name='stripe_webhook'),
    path('api/payment-status/', views.get_payment_status, name='payment_status'),
    path('driverFinances/', views.driverFinancesView, name="DriverFinancesPage"),
    path("api/driver/invoices/weeks/", views.driver_invoice_weeks, name="driver_invoice_weeks"),
    path('driverForgotPassword/', views.driverForgotPasswordView, name="driverForgotPasswordPage"),

    path('contactAdmin/', views.contactAdminView, name='contactAdminPage'), 
    path('api/contact-admin/', views.contact_admin_api, name='contact_admin_api'),

    path('', views.landingView, name='landingPage'),

    path('api/auth/send-otp/', views.send_otp, name='send_otp'),
    path('api/auth/verify-otp/', views.verify_otp, name='verify_otp'),
    path('api/auth/change-password/', views.change_password, name='change_password'),
    path('api/driver/change-password/', views.change_password_driver, name='change_password_driver'),


    

]
