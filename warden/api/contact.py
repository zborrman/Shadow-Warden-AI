"""
warden/api/contact.py
──────────────────────
Public contact-form endpoint — extracted from main.py (architecture Phase 3).

Self-contained: only stdlib SMTP + env config, no gateway state. The route path
and behaviour are identical to the previous inline handler; the route-inventory
guard (test_route_inventory.py) verifies the move changed nothing externally.
"""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from warden.config import settings

log = logging.getLogger("warden.api.contact")

router = APIRouter(tags=["Public"])


class ContactRequest(BaseModel):
    name:    str
    email:   str
    subject: str
    message: str
    company: str = ""


@router.post("/api/contact")
async def contact(body: ContactRequest):
    """Send a contact-form message to the configured SMTP address."""
    smtp_host = settings.smtp_host
    smtp_port = settings.smtp_port
    smtp_user = settings.smtp_user
    smtp_pass = settings.smtp_pass
    to_email  = settings.contact_to_email

    text_parts = [
        f"Name:    {body.name}",
        f"Email:   {body.email}",
        f"Company: {body.company}" if body.company else "",
        f"Topic:   {body.subject}",
        "",
        body.message,
    ]
    text = "\n".join(p for p in text_parts if p is not None)

    if not smtp_host or not smtp_user:
        log.warning("contact form: SMTP not configured — logging message only")
        log.info("contact_form_submission name=%s email=%s subject=%s", body.name, body.email, body.subject)
        return {"ok": True}

    try:
        msg = MIMEText(text, "plain", "utf-8")
        msg["Subject"] = f"[Shadow Warden] {body.subject}"
        msg["From"]    = smtp_user
        msg["To"]      = to_email
        msg["Reply-To"] = body.email

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as srv:
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, [to_email], msg.as_string())

        log.info("contact form sent: from=%s subject=%s", body.email, body.subject)
        return {"ok": True}
    except Exception as exc:
        log.error("contact form send failed: %s", exc)
        raise HTTPException(
            500, "Failed to send message. Please email vz@shadow-warden-ai.com directly."
        ) from exc
