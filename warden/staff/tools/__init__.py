"""Staff tool registry — all tool handlers available to digital employees."""
from __future__ import annotations

from warden.staff.tools.bdr import BDR_TOOL_HANDLERS, BDR_TOOLS
from warden.staff.tools.compliance_kyc import COMPLIANCE_TOOL_HANDLERS, COMPLIANCE_TOOLS
from warden.staff.tools.growth import GROWTH_TOOL_HANDLERS, GROWTH_TOOLS
from warden.staff.tools.support import SUPPORT_TOOL_HANDLERS, SUPPORT_TOOLS

STAFF_TOOL_HANDLERS = {
    **BDR_TOOL_HANDLERS,
    **GROWTH_TOOL_HANDLERS,
    **COMPLIANCE_TOOL_HANDLERS,
    **SUPPORT_TOOL_HANDLERS,
}

STAFF_TOOLS = BDR_TOOLS + GROWTH_TOOLS + COMPLIANCE_TOOLS + SUPPORT_TOOLS

__all__ = ["STAFF_TOOL_HANDLERS", "STAFF_TOOLS"]
