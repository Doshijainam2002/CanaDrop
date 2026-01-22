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

# 🎯 TARGET PHARMACY (PROD)
PHARMACY_ID = 1


class Command(BaseCommand):
    help = (
        "Delete ALL related data for a pharmacy "
        "(orders, tracking, images, invoices, tickets, points) "
        "but KEEP the pharmacy record."
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
            pharmacy = Pharmacy.objects.get(id=PHARMACY_ID)
        except Pharmacy.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"❌ Pharmacy ID {PHARMACY_ID} not found"))
            return

        self.stdout.write(f"\n🔍 Target pharmacy:")
        self.stdout.write(f" - ID {pharmacy.id}: {pharmacy.name}")

        # -----------------------------
        # RELATED DATA
        # -----------------------------
        orders = DeliveryOrder.objects.filter(pharmacy=pharmacy)

        order_images = OrderImage.objects.filter(order__in=orders)
        order_tracking = OrderTracking.objects.filter(order__in=orders)

        invoices = Invoice.objects.filter(pharmacy=pharmacy)
        contact_tickets = ContactAdmin.objects.filter(pharmacy=pharmacy)
        cc_points = CCPointsAccount.objects.filter(pharmacy=pharmacy)

        # -----------------------------
        # SUMMARY
        # -----------------------------
        self.stdout.write("\n📊 Cleanup summary (pharmacy record will be kept):")
        self.stdout.write(f"DeliveryOrders: {orders.count()}")
        self.stdout.write(f"OrderImages: {order_images.count()}")
        self.stdout.write(f"OrderTracking: {order_tracking.count()}")
        self.stdout.write(f"Invoices: {invoices.count()}")
        self.stdout.write(f"ContactAdmin tickets: {contact_tickets.count()}")
        self.stdout.write(f"CCPointsAccount: {cc_points.count()}")
        self.stdout.write(f"Pharmacy row: WILL BE KEPT")

        if dry_run:
            self.stdout.write("\n🟡 DRY RUN — no data deleted\n")
            return

        # -----------------------------
        # HARD DELETE (KEEP PHARMACY)
        # -----------------------------
        with transaction.atomic():
            order_images.delete()
            order_tracking.delete()
            orders.delete()
            invoices.delete()
            contact_tickets.delete()
            cc_points.delete()

        self.stdout.write("\n✅ PHARMACY DATA CLEANUP COMPLETED (PHARMACY KEPT)\n")
