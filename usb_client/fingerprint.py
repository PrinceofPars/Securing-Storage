"""
fingerprint.py — Hardware Fingerprinter Module
===============================================
Extracts platform-specific hardware identifiers and produces a
deterministic SHA-256 hash representing the host machine.

Identifiers collected (cross-platform):
  • CPU ID / processor string
  • System / Motherboard UUID (via dmidecode on Linux, WMI on Windows,
    system_profiler on macOS)
  • OS architecture (x86_64, ARM64, etc.)
  • Machine hostname (secondary disambiguation)

The hash is deterministic for the same hardware but unique across
different physical machines, making it suitable as a host identity token.

Compatibility: Python 3.8+ | Windows, Linux, macOS
"""

import hashlib
import json
import logging
import os
import platform
import re
import subprocess
import sys
import uuid
from typing import Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Platform-Specific UUID Extractors
# ──────────────────────────────────────────────────────────────────────────────

def _get_uuid_windows() -> Optional[str]:
    """
    Query the system UUID via WMI on Windows.
    Uses 'wmic csproduct get UUID' which returns the SMBIOS UUID.
    """
    try:
        result = subprocess.run(
            ['wmic', 'csproduct', 'get', 'UUID'],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
        # Output is: ['UUID', '<actual-uuid>'] — take the second line
        for line in lines:
            if line and line.upper() != 'UUID' and len(line) > 8:
                return line
    except Exception as e:
        logger.warning(f"Windows UUID extraction failed: {e}")
    return None


def _get_uuid_linux() -> Optional[str]:
    """
    Attempt multiple strategies to get a machine UUID on Linux:
      1. /etc/machine-id (most reliable, set at OS install time)
      2. /proc/sys/kernel/random/boot_id  (changes on reboot — less stable)
      3. dmidecode system-uuid (requires root)
    """
    # Strategy 1: /etc/machine-id
    try:
        mid_path = '/etc/machine-id'
        if os.path.exists(mid_path):
            with open(mid_path, 'r') as f:
                mid = f.read().strip()
                if mid and len(mid) >= 8:
                    return mid
    except Exception as e:
        logger.warning(f"machine-id read failed: {e}")

    # Strategy 2: dmidecode (may need sudo)
    try:
        result = subprocess.run(
            ['dmidecode', '-s', 'system-uuid'],
            capture_output=True, text=True, timeout=5
        )
        uid = result.stdout.strip()
        if uid and len(uid) > 8 and 'Permission denied' not in uid:
            return uid
    except Exception as e:
        logger.debug(f"dmidecode failed: {e}")

    # Strategy 3: boot_id (last resort, reboots change this)
    try:
        boot_path = '/proc/sys/kernel/random/boot_id'
        if os.path.exists(boot_path):
            with open(boot_path, 'r') as f:
                return f.read().strip()
    except Exception as e:
        logger.debug(f"boot_id read failed: {e}")

    return None


def _get_uuid_macos() -> Optional[str]:
    """
    Retrieve the hardware UUID on macOS via system_profiler.
    """
    try:
        result = subprocess.run(
            ['system_profiler', 'SPHardwareDataType'],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if 'Hardware UUID' in line or 'UUID' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    uid = parts[-1].strip()
                    if uid:
                        return uid
    except Exception as e:
        logger.warning(f"macOS UUID extraction failed: {e}")
    return None


def _get_system_uuid() -> str:
    """
    Dispatch to the correct platform-specific UUID extractor.
    Falls back to a uuid.getnode()-derived value (MAC address based) if
    all platform methods fail — stable but less unique.
    """
    system = platform.system().lower()
    uid: Optional[str] = None

    if system == 'windows':
        uid = _get_uuid_windows()
    elif system == 'linux':
        uid = _get_uuid_linux()
    elif system == 'darwin':
        uid = _get_uuid_macos()

    if uid:
        # Normalise: strip whitespace, dashes, lowercase
        uid = re.sub(r'[\s-]', '', uid).lower()
        return uid

    # Fallback: MAC address node (uuid.getnode returns 48-bit int)
    node = uuid.getnode()
    logger.warning("Using MAC-based fallback UUID — may change if NIC changes.")
    return format(node, 'x').zfill(12)


# ──────────────────────────────────────────────────────────────────────────────
# CPU String Extraction
# ──────────────────────────────────────────────────────────────────────────────

def _get_cpu_id() -> str:
    """
    Extract a platform-appropriate CPU identifier string.
    This is the full processor name/model, which is stable across reboots.
    """
    system = platform.system().lower()

    # Windows: WMIC processor name
    if system == 'windows':
        try:
            result = subprocess.run(
                ['wmic', 'cpu', 'get', 'Name'],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
            for line in lines:
                if line.upper() != 'NAME' and line:
                    return line
        except Exception as e:
            logger.debug(f"WMIC CPU name failed: {e}")

    # Linux: /proc/cpuinfo
    elif system == 'linux':
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line.lower():
                        return line.split(':')[-1].strip()
        except Exception as e:
            logger.debug(f"/proc/cpuinfo read failed: {e}")

    # macOS: sysctl
    elif system == 'darwin':
        try:
            result = subprocess.run(
                ['sysctl', '-n', 'machdep.cpu.brand_string'],
                capture_output=True, text=True, timeout=5
            )
            cpu = result.stdout.strip()
            if cpu:
                return cpu
        except Exception as e:
            logger.debug(f"sysctl CPU failed: {e}")

    # Fallback to Python's platform.processor()
    cpu = platform.processor()
    return cpu if cpu else 'unknown_cpu'


# ──────────────────────────────────────────────────────────────────────────────
# Main Public API
# ──────────────────────────────────────────────────────────────────────────────

def get_hardware_components() -> dict:
    """
    Collect all hardware identifiers from the current host.

    Returns a dict with:
      - cpu_id:       CPU model/brand string
      - system_uuid:  Board/system UUID or machine-id
      - os_arch:      e.g. 'AMD64', 'arm64', 'x86_64'
      - hostname:     System hostname (secondary disambiguator)
      - platform:     OS name (Windows, Linux, Darwin)
    """
    return {
        'cpu_id':      _get_cpu_id(),
        'system_uuid': _get_system_uuid(),
        'os_arch':     platform.machine(),
        'hostname':    platform.node(),
        'platform':    platform.system()
    }


def generate_fingerprint(components: Optional[dict] = None) -> str:
    """
    Generate a deterministic SHA-256 hardware fingerprint.

    Process:
      1. Collect hardware components (or use provided dict).
      2. Normalise strings (strip, lowercase).
      3. Serialise in a stable, sorted JSON format.
      4. Hash with SHA-256.

    Args:
        components: Pre-collected hardware dict (useful for testing/mocking).

    Returns:
        64-character hex string (SHA-256 digest).
    """
    if components is None:
        components = get_hardware_components()

    # Normalise each field
    normalised = {
        k: v.strip().lower() if isinstance(v, str) else str(v)
        for k, v in components.items()
    }

    # Sort keys for deterministic output regardless of dict insertion order
    canonical_str = json.dumps(normalised, sort_keys=True, separators=(',', ':'))

    fingerprint = hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()
    return fingerprint


def display_fingerprint_info() -> str:
    """
    Human-readable summary of the current host fingerprint.
    Returns the fingerprint hash and prints component details.
    """
    components = get_hardware_components()
    fingerprint = generate_fingerprint(components)

    print("\n" + "═" * 60)
    print("  🔎  Hardware Fingerprint Report")
    print("═" * 60)
    print(f"  Platform  : {components['platform']}")
    print(f"  Hostname  : {components['hostname']}")
    print(f"  CPU       : {components['cpu_id']}")
    print(f"  OS Arch   : {components['os_arch']}")
    print(f"  Sys UUID  : {components['system_uuid']}")
    print("─" * 60)
    print(f"  FINGERPRINT (SHA-256):")
    print(f"  {fingerprint[:32]}")
    print(f"  {fingerprint[32:]}")
    print("═" * 60 + "\n")

    return fingerprint


# ──────────────────────────────────────────────────────────────────────────────
# CLI entrypoint (for standalone testing)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    fp = display_fingerprint_info()
    print(f"Fingerprint: {fp}")
