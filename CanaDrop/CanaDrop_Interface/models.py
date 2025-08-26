from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone



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

class Pharmacy(models.Model):
    name = models.CharField(max_length=255)
    store_address = models.TextField()
    city = models.CharField(max_length=100)
    province = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128, default="123456")  # Django hash length
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Hash the password if it's not already hashed
        if self.password and not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.name

class Driver(models.Model):
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    vehicle_number = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class DeliveryDistanceRate(models.Model):
    min_distance_km = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    max_distance_km = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)  # Null = no upper limit
    rate = models.DecimalField(max_digits=8, decimal_places=2)  # Flat rate

    def __str__(self):
        if self.max_distance_km:
            return f"{self.min_distance_km}-{self.max_distance_km} km = ${self.rate}"
        return f"{self.min_distance_km}+ km = ${self.rate}"



class DeliveryOrder(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
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
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    rate = models.DecimalField(max_digits=8, decimal_places=2, default=0)  # Filled from DeliveryLocationRate
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Order #{self.id} by {self.pharmacy.name}"



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

    def __str__(self):
        return f"Invoice {self.id} for {self.pharmacy.name}"

    # Optional: auto-update status if past due
    def save(self, *args, **kwargs):
        if self.status != 'paid' and self.due_date < timezone.now().date():
            self.status = 'past_due'
        super().save(*args, **kwargs)



class DriverPayment(models.Model):
    driver = models.ForeignKey(Driver, on_delete=models.CASCADE, related_name='payments')
    order = models.ForeignKey(DeliveryOrder, on_delete=models.CASCADE, related_name='driver_payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    paid = models.BooleanField(default=False)
    paid_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"Payment to {self.driver.name} for Order #{self.order.id}"


# _________________________________________________________________________________________________________________
# AUDIT TABLES
# _________________________________________________________________________________________________________________


class OrderTracking(models.Model):
    STEP_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted by Driver'),
        ('picked_up', 'Picked Up'),
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

    def __str__(self):
        return f"Order #{self.order.id} - {self.step} at {self.timestamp}"



class DriverPaymentTracking(models.Model):
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
    ]

    payment = models.ForeignKey(DriverPayment, on_delete=models.CASCADE, related_name='tracking_entries')
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES)
    processed_by = models.CharField(max_length=100, blank=True, null=True)  # admin or system user
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    note = models.TextField(blank=True, null=True)  # optional remarks

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"Payment #{self.payment.id} - {self.status} at {self.timestamp}"



