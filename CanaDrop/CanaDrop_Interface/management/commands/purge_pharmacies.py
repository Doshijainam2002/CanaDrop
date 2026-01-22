from django.core.management.base import BaseCommand
from django.db import transaction

from CanaDrop_Interface.models import (
    Pharmacy,
    DeliveryOrder,
    OrderImage,
    OrderTracking,
    Invoice,
    ContactAdmin,
    CCPointsAccount,
)

# 🔴 PHARMACY IDS TO PURGE (PRODUCTION)
PHARMACY_IDS = [4, 2, 13, 3, 11, 5]


class Command(BaseCommand):
    help = "Fully purge pharmacies and ALL related data (orders, invoices, tickets, audit, points)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what will be deleted without deleting anything",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        pharmacies = Pharmacy.objects.filter(id__in=PHARMACY_IDS)

        self.stdout.write("\n🔍 Target pharmacies:")
        for p in pharmacies:
            self.stdout.write(f" - ID {p.id}: {p.name}")

        # -----------------------------
        # RELATED DATA
        # -----------------------------
        orders = DeliveryOrder.objects.filter(pharmacy__in=pharmacies)

        order_images = OrderImage.objects.filter(order__in=orders)
        order_tracking = OrderTracking.objects.filter(order__in=orders)

        invoices = Invoice.objects.filter(pharmacy__in=pharmacies)
        contact_tickets = ContactAdmin.objects.filter(pharmacy__in=pharmacies)
        cc_points = CCPointsAccount.objects.filter(pharmacy__in=pharmacies)

        # -----------------------------
        # SUMMARY
        # -----------------------------
        self.stdout.write("\n📊 Deletion summary:")
        self.stdout.write(f"Pharmacies: {pharmacies.count()}")
        self.stdout.write(f"DeliveryOrders: {orders.count()}")
        self.stdout.write(f"OrderImages: {order_images.count()}")
        self.stdout.write(f"OrderTracking: {order_tracking.count()}")
        self.stdout.write(f"Invoices: {invoices.count()}")
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
            invoices.delete()
            contact_tickets.delete()
            cc_points.delete()
            pharmacies.delete()

        self.stdout.write("\n✅ FULL PHARMACY PURGE COMPLETED SUCCESSFULLY\n")
