from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
from datetime import datetime
from django.core.exceptions import ValidationError



class AdminUser(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    
    # Address fields
    street_address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    province = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)

    # Password field with default
    password = models.CharField(max_length=255, default='Admin123456')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name or ''} (Admin)"

    # Override save to hash password automatically
    def save(self, *args, **kwargs):
        # If the password is not hashed yet, hash it
        if self.password and not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    # Optional: method to check password
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
    class Meta:
        db_table = 'canadrop_interface_adminuser'  


def default_business_hours():
    return {
        "Mon": {"open": "09:00", "close": "18:00"},
        "Tue": {"open": "09:00", "close": "18:00"},
        "Wed": {"open": "09:00", "close": "18:00"},
        "Thu": {"open": "09:00", "close": "18:00"},
        "Fri": {"open": "09:00", "close": "18:00"},
        "Sat": "closed",
        "Sun": "closed",
    }


class Pharmacy(models.Model):
    name = models.CharField(max_length=255)
    store_address = models.TextField()
    city = models.CharField(max_length=100)
    province = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128, default="123456")
    created_at = models.DateTimeField(auto_now_add=True)

    active = models.BooleanField(default=True, db_index=True)

    business_hours = models.JSONField(default=default_business_hours)

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def is_open_now(self):
        """
        Uses UTC internally (timezone.now()) and converts to settings.USER_TIMEZONE
        (America/Toronto) for business-hours comparison.
        """
        # UTC -> User timezone
        now_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE)

        day = now_local.strftime("%a")  # "Mon", "Tue", ...
        today = self.business_hours.get(day)

        if not today or today == "closed":
            return False

        open_time = datetime.strptime(today["open"], "%H:%M").time()
        close_time = datetime.strptime(today["close"], "%H:%M").time()

        return open_time <= now_local.time() <= close_time

    def __str__(self):
        return self.name

    class Meta:
        db_table = "canadrop_interface_pharmacy"


class Driver(models.Model):
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128, default="123456")  # Django hash length
    vehicle_number = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # NEW
    active = models.BooleanField(default=True, db_index=True)
    identity_url = models.URLField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'canadrop_interface_driver'


class DeliveryDistanceRate(models.Model):
    min_distance_km = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    max_distance_km = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)  # Null = no upper limit
    rate = models.DecimalField(max_digits=8, decimal_places=2)  # Flat rate

    def __str__(self):
        if self.max_distance_km:
            return f"{self.min_distance_km}-{self.max_distance_km} km = ${self.rate}"
        return f"{self.min_distance_km}+ km = ${self.rate}"
    
    class Meta:
        db_table = 'canadrop_interface_deliverydistancerate'



class DeliveryOrder(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('inTransit', 'In Transit'),
        ('picked_up', 'Picked Up'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    pharmacy = models.ForeignKey(Pharmacy, on_delete=models.CASCADE, related_name='orders')
    driver = models.ForeignKey(Driver, on_delete=models.SET_NULL, null=True, blank=True, related_name='orders')
    pickup_address = models.TextField()
    pickup_city = models.CharField(max_length=100, default="Kitchener")  # New field
    pickup_day = models.DateField()
    drop_address = models.TextField()
    drop_city = models.CharField(max_length=100)
    signature_required = models.BooleanField(default=False)
    id_verification_required = models.BooleanField(default=False)
    alternate_contact = models.CharField(max_length=20, blank=True, null=True)
    delivery_notes = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    rate = models.DecimalField(max_digits=8, decimal_places=2, default=0)  # Filled from DeliveryLocationRate
    customer_name = models.CharField(max_length=150, default="John Doe")
    customer_phone = models.CharField(max_length=10, default="0000000000")
    signature_ack_url = models.URLField(null=True, blank=True)
    id_verified = models.BooleanField(default=False)
    is_delivered = models.BooleanField(default=False)
    delivered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Order #{self.id} by {self.pharmacy.name}"

    class Meta:
        db_table = 'canadrop_interface_deliveryorder'



class OrderImage(models.Model):
    STAGE_CHOICES = [
        ('handover', 'Pharmacy Handover'),
        ('pickup', 'Driver Pickup'),
        ('delivered', 'Delivered'),
    ]

    order = models.ForeignKey(DeliveryOrder, on_delete=models.CASCADE, related_name='images')
    image_url = models.URLField()  # URL to cloud bucket
    stage = models.CharField(max_length=20, choices=STAGE_CHOICES)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.stage} image for Order #{self.order.id}"
    
    class Meta:
        db_table = 'canadrop_interface_orderimage'


class Invoice(models.Model):
    STATUS_CHOICES = [
        ('generated', 'Generated'),
        ('paid', 'Paid'),
        ('past_due', 'Past Due'),
    ]

    pharmacy = models.ForeignKey(Pharmacy, on_delete=models.CASCADE, related_name='invoices')
    start_date = models.DateField()
    end_date = models.DateField()
    total_orders = models.IntegerField()
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    due_date = models.DateField()  # New field for invoice due date
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='generated')
    created_at = models.DateTimeField(auto_now_add=True)
    pdf_url = models.URLField(blank=True, null=True)  # Generated invoice PDF link
    stripe_payment_id = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"Invoice {self.id} for {self.pharmacy.name}"

    def save(self, *args, **kwargs):
        today_local = timezone.localtime(timezone.now(), settings.USER_TIMEZONE).date()
        if self.status != 'paid' and self.due_date < today_local:
            self.status = 'past_due'
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'canadrop_interface_invoice'



class DriverInvoice(models.Model):
    STATUS_CHOICES = [
        ('generated', 'Generated'),
        ('paid', 'Paid'),
    ]

    driver = models.ForeignKey("Driver", on_delete=models.CASCADE, related_name="invoices")
    start_date = models.DateField()
    end_date = models.DateField()
    total_deliveries = models.IntegerField()
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    due_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="generated")
    created_at = models.DateTimeField(auto_now_add=True)
    pdf_url = models.URLField(blank=True, null=True)  # generated invoice PDF link

    def __str__(self):
        return f"Invoice {self.id} for Driver {self.driver.name}"
    
    class Meta:
        db_table = 'canadrop_interface_driverinvoice'


class ContactAdmin(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
    ]

    SUBJECT_CHOICES = [
        # Account / Login issues
        ('account_creation', 'Account Creation Issue'),
        ('login_problem', 'Login / Authentication Problem'),
        ('password_reset', 'Password Reset Issue'),
        ('profile_update', 'Profile / Information Update Issue'),

        # Order related
        ('order_placement', 'Order Placement Issue'),
        ('order_cancellation', 'Order Cancellation Issue'),
        ('order_tracking', 'Order Tracking / Status Issue'),
        ('order_payment', 'Order Payment / Rate Issue'),

        # Delivery related
        ('pickup_issue', 'Pickup Issue by Driver'),
        ('delivery_delay', 'Delivery Delay'),
        ('delivery_incorrect', 'Incorrect Delivery / Item Issue'),
        ('driver_unavailable', 'Driver Unavailable / Assignment Issue'),

        # Invoice / Payment related
        ('invoice_generated', 'Invoice Generated Issue'),
        ('invoice_payment', 'Invoice Payment / Stripe Issue'),
        ('driver_invoice', 'Driver Invoice / Payment Issue'),

        # Technical / App issues
        ('technical_bug', 'Technical / App Bug'),
        ('cloud_storage', 'Cloud / Image Upload Issue'),
        ('notification', 'Notification / Alert Issue'),

        # Feedback
        ('feedback', 'Feedback / Suggestion'),

        # Catch-all
        ('other', 'Other'),
    ]

    # Either a pharmacy or a driver can contact admin
    pharmacy = models.ForeignKey(Pharmacy, on_delete=models.SET_NULL, null=True, blank=True, related_name='contacts')
    driver = models.ForeignKey(Driver, on_delete=models.SET_NULL, null=True, blank=True, related_name='contacts')

    subject = models.CharField(max_length=50, choices=SUBJECT_CHOICES)
    other_subject = models.CharField(max_length=255, blank=True, null=True)  # Only used if subject='other'
    message = models.TextField()
    admin_response = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        sender = self.pharmacy.name if self.pharmacy else self.driver.name if self.driver else "Unknown"
        subject_display = self.other_subject if self.subject == 'other' else self.get_subject_display()
        return f"Contact from {sender} - {subject_display}"

    class Meta:
        db_table = 'canadrop_interface_contactadmin'
        ordering = ['-created_at']


class PaymentInformation(models.Model):
    """
    Generic payment information storage.
    Each row represents one payment method or payment configuration.
    """

    PAYMENT_TYPE_CHOICES = [
        ("eft", "Electronic Funds Transfer (EFT)"),
        ("cheque", "Cheque"),
        ("interac", "Interac e-Transfer"),
        ("wire", "Wire Transfer"),
        ("other", "Other"),
    ]

    # What this row represents
    payment_type = models.CharField(
        max_length=50,
        choices=PAYMENT_TYPE_CHOICES,
        help_text="Type of payment method"
    )

    # Human readable name
    label = models.CharField(
        max_length=255,
        help_text="Display name (e.g. 'Primary EFT Account')"
    )

    # Flexible data storage
    data = models.JSONField(
        help_text="JSON payload containing payment details"
    )

    # Metadata
    is_active = models.BooleanField(
        default=True,
        help_text="Only one active record per payment_type should exist"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    updated_by = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Admin user who last updated this"
    )

    class Meta:
        verbose_name = "Payment Information"
        verbose_name_plural = "Payment Information"
        ordering = ["payment_type", "-is_active", "-updated_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["payment_type"],
                condition=models.Q(is_active=True),
                name="unique_active_payment_type"
            )
        ]

    def __str__(self):
        return f"{self.label} ({self.payment_type}, Active: {self.is_active})"

    def clean(self):
        if not isinstance(self.data, dict):
            raise ValidationError("data must be a JSON object")

    def save(self, *args, **kwargs):
        """
        Ensure only one active entry per payment_type
        """
        if self.is_active:
            PaymentInformation.objects.filter(
                payment_type=self.payment_type,
                is_active=True
            ).exclude(pk=self.pk).update(is_active=False)

        super().save(*args, **kwargs)

    @classmethod
    def get_active(cls, payment_type):
        """
        Get active payment info for a given type
        """
        return cls.objects.filter(
            payment_type=payment_type,
            is_active=True
        ).first()



# _________________________________________________________________________________________________________________
# AUDIT TABLES
# _________________________________________________________________________________________________________________


class OrderTracking(models.Model):
    STEP_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted by Driver'),
        ('picked_up', 'Picked Up'),
        ('inTransit', 'In Transit'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
        ('handover', 'Pharmacy Handover'),
    ]

    order = models.ForeignKey(DeliveryOrder, on_delete=models.CASCADE, related_name='tracking_entries')
    driver = models.ForeignKey(Driver, on_delete=models.SET_NULL, null=True, blank=True, related_name='tracking_entries')
    pharmacy = models.ForeignKey(Pharmacy, on_delete=models.SET_NULL, null=True, blank=True, related_name='tracking_entries')
    step = models.CharField(max_length=20, choices=STEP_CHOICES)
    performed_by = models.CharField(max_length=100, blank=True, null=True)  # driver or pharmacy staff
    timestamp = models.DateTimeField(auto_now_add=True)
    note = models.TextField(blank=True, null=True)  # optional description
    image_url = models.URLField(blank=True, null=True)  # optional proof image

    class Meta:
        ordering = ['timestamp']
        db_table = 'canadrop_interface_ordertracking'

    def __str__(self):
        return f"Order #{self.order.id} - {self.step} at {self.timestamp}"


# class PharmacyTrialOnboarding(models.Model):
#     # -------------------------------
#     # Section 1: Pharmacy Info
#     # -------------------------------
#     pharmacy_name = models.CharField(max_length=255)
#     pharmacy_phone = models.CharField(max_length=20)
#     pharmacy_email = models.EmailField()

#     address_line_1 = models.CharField(max_length=255)
#     city = models.CharField(max_length=100)
#     postal_code = models.CharField(max_length=10)

#     store_hours = models.CharField(
#         max_length=255,
#         help_text="Example: Mon–Fri 9am–7pm"
#     )

#     # -------------------------------
#     # Section 2: Owner / Manager
#     # -------------------------------
#     contact_name = models.CharField(max_length=255)
#     contact_role = models.CharField(
#         max_length=50,
#         choices=[
#             ("owner", "Owner"),
#             ("manager", "Manager"),
#             ("pharmacist", "Pharmacist"),
#         ]
#     )
#     contact_phone = models.CharField(max_length=20)
#     contact_email = models.EmailField()

#     # -------------------------------
#     # Section 3: Trial Delivery Setup
#     # -------------------------------
#     currently_offers_delivery = models.BooleanField(default=False)

#     estimated_deliveries_per_day = models.PositiveIntegerField()

#     DELIVERY_TYPE_CHOICES = [
#         ("same_day", "Same-day"),
#         ("next_day", "Next-day"),
#         ("both", "Both"),
#     ]
#     preferred_delivery_type = models.CharField(
#         max_length=10,
#         choices=DELIVERY_TYPE_CHOICES
#     )

#     same_day_cutoff_time = models.TimeField(
#         null=True,
#         blank=True,
#         help_text="Required if same-day delivery is selected"
#     )

#     delivery_radius_km = models.PositiveIntegerField(
#         help_text="Delivery radius in kilometers"
#     )

#     # -------------------------------
#     # Section 4: Compliance Basics
#     # -------------------------------
#     signature_required = models.BooleanField(default=True)
#     id_verification_required = models.BooleanField(default=False)

#     special_delivery_instructions = models.TextField(
#         blank=True,
#         null=True
#     )

#     # -------------------------------
#     # Section 5: Trial Confirmation
#     # -------------------------------
#     trial_start_date = models.DateField()

#     trial_duration_days = models.PositiveIntegerField(default=7)

#     agreed_delivery_fee = models.DecimalField(
#         max_digits=6,
#         decimal_places=2,
#         help_text="Per delivery fee during trial"
#     )

#     # -------------------------------
#     # Section 6: Consent & Meta
#     # -------------------------------
#     consent_given = models.BooleanField(default=False)

#     created_at = models.DateTimeField(auto_now_add=True)

#     # -------------------------------
#     # Internal Tracking (Optional)
#     # -------------------------------
#     onboarding_notes = models.TextField(blank=True, null=True)

#     STATUS_CHOICES = [
#         ("trial", "Trial"),
#         ("active", "Converted to Active"),
#         ("inactive", "Inactive"),
#     ]
#     status = models.CharField(
#         max_length=10,
#         choices=STATUS_CHOICES,
#         default="trial"
#     )

#     class Meta:
#         ordering = ["-created_at"]
#         verbose_name = "Pharmacy Trial Onboarding"
#         verbose_name_plural = "Pharmacy Trial Onboardings"

#     def __str__(self):
#         return f"{self.pharmacy_name} - Trial"


class PharmacyInfo(models.Model):
    """
    Internal analytics and baseline tracking for pharmacy onboarding.
    Stores initial setup information and delivery preferences for business intelligence.
    """
    # -------------------------------
    # Section 1: Pharmacy Info
    # -------------------------------
    pharmacy_name = models.CharField(max_length=255)
    pharmacy_phone = models.CharField(max_length=20)
    pharmacy_email = models.EmailField()

    address_line_1 = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=10)

    store_hours = models.CharField(
        max_length=255,
        help_text="Example: Mon–Fri 9am–7pm"
    )

    # -------------------------------
    # Section 2: Contact Person
    # -------------------------------
    contact_name = models.CharField(max_length=255)
    contact_role = models.CharField(
        max_length=50,
        choices=[
            ("owner", "Owner"),
            ("manager", "Manager"),
            ("pharmacist", "Pharmacist"),
        ]
    )
    contact_phone = models.CharField(max_length=20)
    contact_email = models.EmailField()

    # -------------------------------
    # Section 3: Delivery Preferences & Analytics Baseline
    # -------------------------------
    currently_offers_delivery = models.BooleanField(default=False)

    estimated_deliveries_per_day = models.PositiveIntegerField()

    DELIVERY_TYPE_CHOICES = [
        ("same_day", "Same-day"),
        ("next_day", "Next-day"),
        ("both", "Both"),
    ]
    preferred_delivery_type = models.CharField(
        max_length=10,
        choices=DELIVERY_TYPE_CHOICES
    )

    delivery_radius_km = models.PositiveIntegerField(
        help_text="Delivery radius in kilometers"
    )

    # -------------------------------
    # Section 4: Compliance & Special Instructions
    # -------------------------------
    signature_required = models.BooleanField(default=True)
    id_verification_required = models.BooleanField(default=False)

    special_delivery_instructions = models.TextField(
        blank=True,
        null=True
    )

    # -------------------------------
    # Section 5: Consent & Meta
    # -------------------------------
    consent_given = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # -------------------------------
    # Internal Notes
    # -------------------------------
    internal_notes = models.TextField(
        blank=True, 
        null=True,
        help_text="Internal notes for analytics and tracking"
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Pharmacy Information"
        verbose_name_plural = "Pharmacy Information"
        db_table = "canadrop_interface_pharmacyinfo"

    def __str__(self):
        return f"{self.pharmacy_name} - {self.city}"



class CCPointsAccount(models.Model):
    # One of these will be set (never both)
    pharmacy = models.OneToOneField(
        "Pharmacy",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="cc_points"
    )
    driver = models.OneToOneField(
        "Driver",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="cc_points"
    )

    points_balance = models.IntegerField(default=0)

    class Meta:
        db_table = "canadrop_interface_ccpointsaccount"
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(pharmacy__isnull=False, driver__isnull=True) |
                    models.Q(pharmacy__isnull=True, driver__isnull=False)
                ),
                name="ccpoints_single_entity_only"
            )
        ]

    def __str__(self):
        if self.pharmacy_id:
            return f"CC Points – Pharmacy ID {self.pharmacy_id}"
        return f"CC Points – Driver ID {self.driver_id}"






