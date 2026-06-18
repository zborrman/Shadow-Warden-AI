"""
warden/integrations/disk_encryption.py  (TC-03)
────────────────────────────────────────────────
Detect host-level disk encryption status for the SOVA tool #68
`tool_disk_encryption_status`.

Supports:
  - Linux  : dm-crypt / LUKS via lsblk
  - Windows: BitLocker via PowerShell Get-BitLockerVolume
  - macOS  : FileVault via diskutil

Runs with a 5-second timeout per sub-process; always returns a result
even if detection fails (status = "unknown").
"""
from __future__ import annotations

import platform
import subprocess


def detect_disk_encryption() -> dict[str, object]:
    """Return disk encryption status of the current host.

    Returns
    -------
    {
        "status": "encrypted" | "not_encrypted" | "partial" | "unknown",
        "method": str,          # e.g. "LUKS", "dm-crypt", "BitLocker", "FileVault"
        "volumes": list[dict],  # per-volume details (may be empty)
        "os": str,
    }
    """
    os_name = platform.system()
    try:
        if os_name == "Linux":
            return _detect_linux()
        elif os_name == "Windows":
            return _detect_windows()
        elif os_name == "Darwin":
            return _detect_macos()
        else:
            return _unknown(os_name, f"Unsupported OS: {os_name}")
    except Exception as exc:
        return _unknown(os_name, str(exc))


# ── Linux ──────────────────────────────────────────────────────────────────────

def _detect_linux() -> dict[str, object]:
    try:
        out = subprocess.check_output(
            ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"],
            timeout=5, text=True, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return _unknown("Linux", str(e))

    import json as _json
    data = _json.loads(out)
    volumes = []
    encrypted_count = 0
    total_count = 0

    def _walk(devices: list[dict]) -> None:
        nonlocal encrypted_count, total_count
        for dev in devices:
            fstype = dev.get("fstype") or ""
            dtype  = dev.get("type") or ""
            if dtype in ("disk", "part", "lvm"):
                total_count += 1
                is_enc = fstype in ("crypto_LUKS", "crypt") or dtype == "crypt"
                if is_enc:
                    encrypted_count += 1
                volumes.append({
                    "name":      dev.get("name"),
                    "type":      dtype,
                    "fstype":    fstype,
                    "encrypted": is_enc,
                })
            if dev.get("children"):
                _walk(dev["children"])

    _walk(data.get("blockdevices", []))

    if total_count == 0:
        return _unknown("Linux", "lsblk returned no block devices")

    status = (
        "encrypted"     if encrypted_count == total_count
        else "partial"  if encrypted_count > 0
        else "not_encrypted"
    )
    method = "LUKS/dm-crypt" if encrypted_count > 0 else "none"
    return {"status": status, "method": method, "volumes": volumes, "os": "Linux"}


# ── Windows ────────────────────────────────────────────────────────────────────

def _detect_windows() -> dict[str, object]:
    ps = (
        "Get-BitLockerVolume | "
        "Select-Object -Property MountPoint,ProtectionStatus,EncryptionMethod | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.check_output(
            ["powershell", "-NonInteractive", "-Command", ps],
            timeout=10, text=True, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return _unknown("Windows", str(e))

    import json as _json
    raw = _json.loads(out)
    if isinstance(raw, dict):
        raw = [raw]

    volumes = []
    encrypted_count = 0
    for v in raw:
        protected = str(v.get("ProtectionStatus", "")).lower() in ("on", "1", "true")
        if protected:
            encrypted_count += 1
        volumes.append({
            "mount":     v.get("MountPoint"),
            "method":    v.get("EncryptionMethod", "unknown"),
            "encrypted": protected,
        })

    total = len(volumes)
    status = (
        "encrypted"     if encrypted_count == total and total > 0
        else "partial"  if encrypted_count > 0
        else "not_encrypted"
    )
    return {
        "status":  status,
        "method":  "BitLocker" if encrypted_count > 0 else "none",
        "volumes": volumes,
        "os":      "Windows",
    }


# ── macOS ──────────────────────────────────────────────────────────────────────

def _detect_macos() -> dict[str, object]:
    try:
        out = subprocess.check_output(
            ["fdesetup", "status"],
            timeout=5, text=True, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return _unknown("Darwin", str(e))

    enabled = "fileVault is On" in out or "On" in out
    return {
        "status":  "encrypted" if enabled else "not_encrypted",
        "method":  "FileVault" if enabled else "none",
        "volumes": [{"name": "system", "encrypted": enabled}],
        "os":      "Darwin",
    }


def _unknown(os_name: str, reason: str) -> dict[str, object]:
    return {"status": "unknown", "method": "unknown", "volumes": [], "os": os_name, "reason": reason}
