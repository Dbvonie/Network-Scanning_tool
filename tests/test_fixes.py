"""Regression tests covering the bug-fixes applied in this PR.

All tests are unit-level — no network access, no root privileges required.
"""
from __future__ import annotations

import errno
import socket
from unittest.mock import MagicMock, patch

import pytest

from scanner.models import Device, FingerprintResult, OSFamily, DeviceType


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1 — DHCP enrich_devices accepts `timeout` keyword
# ─────────────────────────────────────────────────────────────────────────────

class TestDhcpEnrichTimeout:
    """enrich_devices(devices, timeout=N) must not raise TypeError."""

    def test_timeout_kwarg_accepted(self):
        """Calling enrich_devices with timeout= should not crash."""
        from scanner.fingerprint.dhcp_fingerprint import enrich_devices

        devices = [Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")]

        # Patch start_passive_capture so no real sniffing occurs
        with patch(
            "scanner.fingerprint.dhcp_fingerprint.start_passive_capture",
            return_value={},
        ) as mock_cap:
            result = enrich_devices(devices, timeout=5)

        mock_cap.assert_called_once_with(timeout=5)
        assert result is devices  # same list returned

    def test_pre_captured_data_skips_capture(self):
        """When captured dict is supplied, start_passive_capture is never called."""
        from scanner.fingerprint.dhcp_fingerprint import enrich_devices

        devices = [Device(ip="10.0.0.2", mac="AA:BB:CC:DD:EE:02")]

        with patch(
            "scanner.fingerprint.dhcp_fingerprint.start_passive_capture"
        ) as mock_cap:
            enrich_devices(devices, captured={})  # empty pre-captured dict

        mock_cap.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Fix 2 — TCP fingerprint ignores non-SYN-ACK responses
# ─────────────────────────────────────────────────────────────────────────────

class TestTcpProbeFlags:
    """_probe_tcp_syn() must return None for RST/RST-ACK responses."""

    def _make_tcp_resp(self, flags: int, ttl: int = 64, window: int = 65535):
        """Build a minimal fake Scapy response object."""
        from scapy.all import IP, TCP

        tcp_layer = MagicMock()
        tcp_layer.flags = flags
        tcp_layer.window = window
        tcp_layer.options = []

        ip_layer = MagicMock()
        ip_layer.ttl = ttl

        def getitem_side_effect(cls):
            if cls is TCP:
                return tcp_layer
            if cls is IP:
                return ip_layer
            raise KeyError(cls)

        resp = MagicMock()
        resp.haslayer = lambda cls: cls is TCP
        resp.__getitem__ = MagicMock(side_effect=getitem_side_effect)
        return resp

    def test_syn_ack_returns_data(self):
        from scanner.fingerprint.tcp_fingerprint import _probe_tcp_syn

        SYN_ACK = 0x12
        fake_resp = self._make_tcp_resp(flags=SYN_ACK)

        with patch("scanner.fingerprint.tcp_fingerprint.sr1", return_value=fake_resp):
            result = _probe_tcp_syn("10.0.0.1", port=80)

        assert result is not None
        assert "ttl" in result
        assert "window" in result

    def test_rst_returns_none(self):
        from scanner.fingerprint.tcp_fingerprint import _probe_tcp_syn

        RST = 0x04
        fake_resp = self._make_tcp_resp(flags=RST)

        with patch("scanner.fingerprint.tcp_fingerprint.sr1", return_value=fake_resp):
            result = _probe_tcp_syn("10.0.0.1", port=80)

        assert result is None

    def test_rst_ack_returns_none(self):
        from scanner.fingerprint.tcp_fingerprint import _probe_tcp_syn

        RST_ACK = 0x14
        fake_resp = self._make_tcp_resp(flags=RST_ACK)

        with patch("scanner.fingerprint.tcp_fingerprint.sr1", return_value=fake_resp):
            result = _probe_tcp_syn("10.0.0.1", port=80)

        assert result is None

    def test_no_response_returns_none(self):
        from scanner.fingerprint.tcp_fingerprint import _probe_tcp_syn

        with patch("scanner.fingerprint.tcp_fingerprint.sr1", return_value=None):
            result = _probe_tcp_syn("10.0.0.1", port=80)

        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3 — Port state: ECONNREFUSED→closed, other nonzero→filtered
# ─────────────────────────────────────────────────────────────────────────────

class TestPortStateMapping:
    """_scan_port() must correctly classify refused vs filtered states."""

    def _run_scan_port(self, connect_ex_return: int):
        from scanner.core.port_scan import _scan_port

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = connect_ex_return
        mock_sock.gettimeout.return_value = 0.5

        with patch("scanner.core.port_scan.socket.socket", return_value=mock_sock):
            return _scan_port("10.0.0.1", 9999, timeout=0.1)

    def test_zero_is_open(self):
        from scanner.models import PortState

        port = self._run_scan_port(0)
        assert port.state == PortState.OPEN

    def test_econnrefused_is_closed(self):
        from scanner.models import PortState

        port = self._run_scan_port(errno.ECONNREFUSED)
        assert port.state == PortState.CLOSED

    def test_etimedout_is_filtered(self):
        from scanner.models import PortState

        port = self._run_scan_port(errno.ETIMEDOUT)
        assert port.state == PortState.FILTERED

    def test_enetunreach_is_filtered(self):
        from scanner.models import PortState

        port = self._run_scan_port(errno.ENETUNREACH)
        assert port.state == PortState.FILTERED

    def test_socket_timeout_exception_is_filtered(self):
        """socket.timeout exception (raised mid-operation) is also filtered."""
        from scanner.core.port_scan import _scan_port
        from scanner.models import PortState

        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout

        with patch("scanner.core.port_scan.socket.socket", return_value=mock_sock):
            port = _scan_port("10.0.0.1", 9999, timeout=0.1)

        assert port.state == PortState.FILTERED


# ─────────────────────────────────────────────────────────────────────────────
# Fix 5 — MAC lookup: private/randomized MACs + no false-positive fallback
# ─────────────────────────────────────────────────────────────────────────────

class TestMacLookup:
    """mac_to_vendor() must detect private MACs and not return wrong vendors."""

    def test_known_oui_resolved(self):
        from scanner.fingerprint.mac_lookup import mac_to_vendor

        # Apple OUI present in builtin DB
        assert mac_to_vendor("00:03:93:11:22:33") == "Apple"

    def test_unknown_oui_returns_unknown(self):
        from scanner.fingerprint.mac_lookup import mac_to_vendor

        # Made-up OUI not in any database
        assert mac_to_vendor("FE:DC:BA:11:22:33") in ("Unknown", "Private/Randomized")

    def test_private_mac_la_bit_set(self):
        """MAC with LA bit (bit 1 of first octet) returns Private/Randomized."""
        from scanner.fingerprint.mac_lookup import mac_to_vendor

        # 0x02 has LA bit set → locally administered
        assert mac_to_vendor("02:00:00:00:00:01") == "Private/Randomized"
        # 0x06 also has LA bit set
        assert mac_to_vendor("06:AA:BB:CC:DD:EE") == "Private/Randomized"
        # 0xAE: 0b10101110 — LA bit set
        assert mac_to_vendor("AE:BB:CC:DD:EE:FF") == "Private/Randomized"

    def test_globally_administered_not_flagged_private(self):
        """MAC with LA bit clear is NOT flagged as private."""
        from scanner.fingerprint.mac_lookup import mac_to_vendor, _is_private_mac

        # 0x00 — globally administered
        assert not _is_private_mac("00:03:93:11:22:33")
        # Samsung OUI
        assert not _is_private_mac("00:1A:8A:11:22:33")

    def test_no_overly_broad_fallback(self):
        """A MAC whose first 5 chars match a known OUI but differs in 6th char
        should return Unknown, not a spurious vendor."""
        from scanner.fingerprint.mac_lookup import mac_to_vendor

        # "00:03:93" is Apple; "00:03:94" must NOT resolve to Apple
        result = mac_to_vendor("00:03:94:AA:BB:CC")
        assert result != "Apple"

    def test_no_duplicate_oui_samsung_zyxel(self):
        """OUI 00:1A:8A must resolve consistently to one vendor (Samsung)."""
        from scanner.fingerprint.mac_lookup import mac_to_vendor

        vendor = mac_to_vendor("00:1A:8A:00:00:01")
        assert vendor == "Samsung"


# ─────────────────────────────────────────────────────────────────────────────
# Fix 7 — OS classifier: no duplicate Apple/Google rules
# ─────────────────────────────────────────────────────────────────────────────

class TestMacRulesDeduplicated:
    """_MAC_RULES must not contain duplicate first-match-wins entries."""

    def test_apple_appears_once(self):
        from scanner.fingerprint.os_classifier import _MAC_RULES

        apple_rules = [r for r in _MAC_RULES if r[0].upper() == "APPLE"]
        assert len(apple_rules) == 1, (
            f"Expected 1 Apple rule, got {len(apple_rules)}: {apple_rules}"
        )

    def test_google_appears_once(self):
        from scanner.fingerprint.os_classifier import _MAC_RULES

        google_rules = [r for r in _MAC_RULES if r[0].upper() == "GOOGLE"]
        assert len(google_rules) == 1, (
            f"Expected 1 Google rule, got {len(google_rules)}: {google_rules}"
        )

    def test_non_apple_vendor_does_not_trigger_refine_apple(self):
        """classify() with a non-Apple vendor must NOT invoke _refine_apple logic."""
        from scanner.fingerprint.os_classifier import classify

        device = Device(ip="10.0.0.2", mac="00:1A:8A:AA:BB:CC")
        device.mac_vendor = "Samsung"
        device.fingerprint = FingerprintResult(
            os_family=OSFamily.ANDROID,
            confidence=0.75,
            tcp_window=65535,
            tcp_options=["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
            sources={"tcp": "test"},
        )
        result = classify(device)
        # Must remain Android — not promoted to macOS by _refine_apple
        assert result.os_family == OSFamily.ANDROID

    def test_apple_vendor_triggers_refine_apple(self):
        """classify() with an Apple vendor + TCP data must use _refine_apple."""
        from scanner.fingerprint.os_classifier import classify

        device = Device(ip="10.0.0.1", mac="00:03:93:AA:BB:CC")
        device.mac_vendor = "Apple"
        # Provide TCP data that favours macOS
        device.fingerprint = FingerprintResult(
            os_family=OSFamily.MACOS,
            confidence=0.70,
            tcp_window=65535,
            tcp_options=["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
            sources={"tcp": "test"},
        )
        result = classify(device)
        assert result.os_family == OSFamily.MACOS
