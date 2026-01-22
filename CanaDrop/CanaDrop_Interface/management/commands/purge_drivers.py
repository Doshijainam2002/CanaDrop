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


# 🔴 DRIVER IDS TO PURGE (PRODUCTION)
DRIVER_IDS = [1, 11, 3, 5, 2, 4, 7, 9, 10]


class Command(BaseCommand):
    help = "Fully purge drivers and ALL related data (orders, tracking, invoices, tickets, points)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what will be deleted without deleting anything",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        drivers = Driver.objects.filter(id__in=DRIVER_IDS)

        self.stdout.write("\n🔍 Target drivers:")
        for d in drivers:
            self.stdout.write(f" - ID {d.id}: {d.name}")

        # -----------------------------
        # RELATED DATA
        # -----------------------------
        orders = DeliveryOrder.objects.filter(driver__in=drivers)

        order_images = OrderImage.objects.filter(order__in=orders)
        order_tracking = OrderTracking.objects.filter(order__in=orders)

        driver_invoices = DriverInvoice.objects.filter(driver__in=drivers)
        contact_tickets = ContactAdmin.objects.filter(driver__in=drivers)
        cc_points = CCPointsAccount.objects.filter(driver__in=drivers)

        # -----------------------------
        # SUMMARY
        # -----------------------------
        self.stdout.write("\n📊 Deletion summary:")
        self.stdout.write(f"Drivers: {drivers.count()}")
        self.stdout.write(f"DeliveryOrders: {orders.count()}")
        self.stdout.write(f"OrderImages: {order_images.count()}")
        self.stdout.write(f"OrderTracking: {order_tracking.count()}")
        self.stdout.write(f"DriverInvoices: {driver_invoices.count()}")
        self.stdout.write(f"ContactAdmin tickets: {contact_tickets.count()}")
        self.stdout.write(f"CCPointsAccount: {cc_points.count()}")

        if dry_run:
            self.stdout.write("\n🟡 DRY RUN — no data deleted\n")
            return

        # -----------------------------
        # HARD DELETE (FK-SAFE ORDER)
        # -----------------------------
        with transaction.atomic():
            order_images.delete()
            order_tracking.delete()
            orders.delete()
            driver_invoices.delete()
            contact_tickets.delete()
            cc_points.delete()
            drivers.delete()

        self.stdout.write("\n✅ FULL DRIVER PURGE COMPLETED SUCCESSFULLY\n")
