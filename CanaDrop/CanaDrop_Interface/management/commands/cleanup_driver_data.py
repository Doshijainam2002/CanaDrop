from django.core.management.base import BaseCommand
from django.db import transaction

from CanaDrop_Interface.models import (
    Driver,
    DeliveryOrder,
    OrderImage,
    OrderTracking,
    DriverInvoice,
    ContactAdmin,
    CCPointsAccount,
)

# 🎯 TARGET DRIVER (CHANGE PER USE)
DRIVER_ID = 1   # <-- update this before running in PROD


class Command(BaseCommand):
    help = (
        "Delete ALL related data for a driver "
        "(orders, tracking, images, invoices, tickets, points) "
        "but KEEP the driver record."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what will be deleted without deleting anything",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        try:
            driver = Driver.objects.get(id=DRIVER_ID)
        except Driver.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"❌ Driver ID {DRIVER_ID} not found"))
            return

        self.stdout.write("\n🔍 Target driver:")
        self.stdout.write(f" - ID {driver.id}: {driver.name}")

        # -----------------------------
        # RELATED DATA
        # -----------------------------
        orders = DeliveryOrder.objects.filter(driver=driver)

        order_images = OrderImage.objects.filter(order__in=orders)
        order_tracking = OrderTracking.objects.filter(order__in=orders)

        driver_invoices = DriverInvoice.objects.filter(driver=driver)
        contact_tickets = ContactAdmin.objects.filter(driver=driver)
        cc_points = CCPointsAccount.objects.filter(driver=driver)

        # -----------------------------
        # SUMMARY
        # -----------------------------
        self.stdout.write("\n📊 Cleanup summary (driver record will be kept):")
        self.stdout.write(f"DeliveryOrders: {orders.count()}")
        self.stdout.write(f"OrderImages: {order_images.count()}")
        self.stdout.write(f"OrderTracking: {order_tracking.count()}")
        self.stdout.write(f"DriverInvoices: {driver_invoices.count()}")
        self.stdout.write(f"ContactAdmin tickets: {contact_tickets.count()}")
        self.stdout.write(f"CCPointsAccount: {cc_points.count()}")
        self.stdout.write("Driver row: WILL BE KEPT")

        if dry_run:
            self.stdout.write("\n🟡 DRY RUN — no data deleted\n")
            return

        # -----------------------------
        # HARD DELETE (KEEP DRIVER)
        # -----------------------------
        with transaction.atomic():
            order_images.delete()
            order_tracking.delete()
            orders.delete()
            driver_invoices.delete()
            contact_tickets.delete()
            cc_points.delete()

        self.stdout.write("\n✅ DRIVER DATA CLEANUP COMPLETED (DRIVER KEPT)\n")
