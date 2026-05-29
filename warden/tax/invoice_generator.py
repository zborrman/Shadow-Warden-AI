"""
warden/tax/invoice_generator.py
PDF invoice generation for agentic commerce orders.
Uses ReportLab when available; falls back to HTML invoice.
Stores output in MinIO (S3) via existing storage backend.
"""
from __future__ import annotations

import io
import logging
import os
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.tax.invoice")

_COMPANY_NAME    = os.getenv("COMPANY_NAME", "Shadow Warden AI")
_COMPANY_ADDRESS = os.getenv("COMPANY_ADDRESS", "cloud-based")


def _generate_pdf(invoice_data: dict[str, Any]) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        # Header
        story.append(Paragraph(f"<b>{_COMPANY_NAME}</b>", styles["Title"]))
        story.append(Paragraph(f"INVOICE #{invoice_data['invoice_number']}", styles["Heading2"]))
        story.append(Spacer(1, 0.4*cm))

        meta = [
            ["Date:", invoice_data.get("date", "")],
            ["Order ID:", invoice_data.get("order_id", "")],
            ["Tenant:", invoice_data.get("tenant_id", "")],
            ["Merchant:", invoice_data.get("merchant", "")],
        ]
        meta_table = Table(meta, colWidths=[4*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.grey),
            ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.6*cm))

        # Line items
        items = invoice_data.get("items", [])
        rows = [["Description", "Qty", "Unit Price", "Total"]]
        for item in items:
            rows.append([
                item.get("name", "Item"),
                str(item.get("qty", 1)),
                f"${item.get('unit_price', 0):.2f}",
                f"${item.get('qty', 1) * item.get('unit_price', 0):.2f}",
            ])
        rows.append(["", "", "Net:", f"${invoice_data.get('net_amount', 0):.2f}"])
        rows.append(["", "", f"Tax ({invoice_data.get('tax_rate_pct', 0):.1f}%):",
                     f"${invoice_data.get('tax_amount', 0):.2f}"])
        rows.append(["", "", "Total:", f"${invoice_data.get('total_with_tax', 0):.2f}"])

        tbl = Table(rows, colWidths=[9*cm, 2*cm, 3*cm, 2*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#1e293b")),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -2), 0.3, colors.lightgrey),
            ("FONTNAME",    (0, -3), (-1, -1), "Helvetica-Bold"),
        ]))
        story.append(tbl)

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        # Fallback: HTML as bytes
        html = f"""<!DOCTYPE html>
<html><head><title>Invoice {invoice_data['invoice_number']}</title></head>
<body style="font-family:sans-serif;max-width:700px;margin:40px auto">
<h1>{_COMPANY_NAME}</h1>
<h2>Invoice #{invoice_data['invoice_number']}</h2>
<p>Date: {invoice_data.get('date', '')} | Order: {invoice_data.get('order_id', '')}</p>
<p>Merchant: {invoice_data.get('merchant', '')} | Tenant: {invoice_data.get('tenant_id', '')}</p>
<hr/>
<p>Net: ${invoice_data.get('net_amount', 0):.2f}</p>
<p>Tax ({invoice_data.get('tax_rate_pct', 0):.1f}%): ${invoice_data.get('tax_amount', 0):.2f}</p>
<p><strong>Total: ${invoice_data.get('total_with_tax', 0):.2f}</strong></p>
</body></html>"""
        return html.encode()


class InvoiceGenerator:

    def create(self, order_data: dict[str, Any], tax_result: Any) -> dict[str, Any]:
        invoice_number = f"INV-{datetime.now(UTC).strftime('%Y%m')}-{order_data.get('id', '')[:8].upper()}"
        invoice_data = {
            "invoice_number": invoice_number,
            "date":           datetime.now(UTC).strftime("%Y-%m-%d"),
            "order_id":       order_data.get("id", ""),
            "tenant_id":      order_data.get("tenant_id", ""),
            "merchant":       order_data.get("store_url", ""),
            "items":          order_data.get("items", []),
            "net_amount":     order_data.get("total", 0),
            "tax_rate_pct":   getattr(tax_result, "rate", 0) * 100 if tax_result else 0,
            "tax_amount":     getattr(tax_result, "tax_amount", 0) if tax_result else 0,
            "total_with_tax": getattr(tax_result, "total_with_tax", order_data.get("total", 0)) if tax_result else order_data.get("total", 0),
        }

        pdf_bytes = _generate_pdf(invoice_data)

        # Store in MinIO if available
        s3_key = f"warden-invoices/{order_data.get('tenant_id', 'default')}/{invoice_number}.pdf"
        stored_url = self._store(pdf_bytes, s3_key)

        return {
            "invoice_number": invoice_number,
            "s3_key":         s3_key,
            "url":            stored_url,
            "size_bytes":     len(pdf_bytes),
            "content_type":   "application/pdf",
            "data":           invoice_data,
        }

    def _store(self, data: bytes, key: str) -> str:
        try:
            from warden.storage.s3 import get_storage
            storage = get_storage()
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                storage.put_object_async("warden-invoices", key, data)
            )
            return f"/invoices/{key}"
        except Exception as exc:
            log.debug("Invoice S3 store skipped: %s", exc)
            return f"/invoices/{key}"
