"""Unit tests for Live Testing module, attacks, threat intel, and engine integration."""
import pytest
from unittest.mock import MagicMock
import numpy as np
import pandas as pd

from attacks.attack_base import BaseAttack
from attacks.port_scan_attack import PortScanAttack
from attacks.dos_attack import DoSAttack
from attacks.bruteforce_attack import BruteForceAttack
from threat_intel.mitre_map import get_technique, all_techniques
from threat_intel import ip_reputation
from threat_intel import intel_store
from target_app.app import app as target_flask_app
from src.core.types import FlowBatch
from live.flow_aggregator import _FlowRecord


class TestSafetyScope:
    """Tests ensuring safety enforcement in BaseAttack."""

    def test_localhost_allowed(self):
        """127.0.0.1 and localhost must not raise SystemExit."""
        attack = PortScanAttack(target="127.0.0.1", port=5000, duration=1)
        assert attack.target == "127.0.0.1"

    def test_non_localhost_refused(self):
        """Any external target must trigger refusal and exit."""
        with pytest.raises(SystemExit):
            PortScanAttack(target="8.8.8.8", port=5000, duration=1)

    def test_external_domain_refused(self):
        """External domain name must trigger refusal and exit."""
        with pytest.raises(SystemExit):
            DoSAttack(target="evil.com", port=5000, duration=1)


class TestTargetApp:
    """Tests for the Flask toy target app."""

    @pytest.fixture
    def client(self):
        target_flask_app.config["TESTING"] = True
        with target_flask_app.test_client() as client:
            yield client

    def test_index_route(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Cyber IDS Test Target" in resp.data

    def test_api_items_route(self, client):
        resp = client.get("/api/items")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "items" in data
        assert data["total"] == 5

    def test_login_invalid(self, client):
        resp = client.post("/login", json={"username": "admin", "password": "wrongpassword"})
        assert resp.status_code == 401

    def test_login_valid(self, client):
        resp = client.post("/login", json={"username": "admin", "password": "password123"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"


class TestThreatIntel:
    """Tests for MITRE mapping, IP reputation, and SQLite intel store."""

    def test_mitre_map_known(self):
        t_id, t_name = get_technique("PortScan")
        assert t_id == "T1046"
        assert "Discovery" in t_name

        t_id, t_name = get_technique("DoS")
        assert t_id == "T1498"

        t_id, t_name = get_technique("BruteForce")
        assert t_id == "T1110"

    def test_mitre_map_unknown(self):
        t_id, _ = get_technique("NonExistentAttack")
        assert t_id == "T0000"

    def test_ip_reputation(self):
        test_ip = "127.0.0.99"
        ip_reputation.record_alert(test_ip, "HIGH")
        score = ip_reputation.get_score(test_ip)
        assert score >= 10.0

        top = ip_reputation.top_ips(5)
        assert any(item["ip"] == test_ip for item in top)

    def test_intel_store_persistence(self):
        intel_store.init_db()

        mock_alert = MagicMock()
        mock_alert.severity = "HIGH"
        mock_alert.attack_type = "DoS"
        mock_alert.final_score = 0.95
        mock_alert.reasons = ["High flow rate"]

        intel_store.record(mock_alert, "127.0.0.1", "T1498")

        summary = intel_store.query_summary()
        assert "DoS" in summary["type_counts"]

        history = intel_store.query_ip_history("127.0.0.1")
        assert len(history) > 0
        assert history[0]["source_ip"] == "127.0.0.1"


class TestFlowAggregatorRecord:
    """Tests for packet feature aggregation."""

    def test_flow_record_accumulation(self):
        rec = _FlowRecord(dst_port=5000, src_port=54321)
        rec.add_packet(is_forward=True, pkt_len=100, syn=1, ack=0, win=65535)
        rec.add_packet(is_forward=False, pkt_len=60, syn=0, ack=1, win=65535)

        features = rec.to_feature_row()
        assert features["Destination Port"] == 5000.0
        assert features["Total Fwd Packets"] == 1.0
        assert features["Total Backward Packets"] == 1.0
        assert features["SYN Flag Count"] == 1.0
        assert features["ACK Flag Count"] == 1.0
        assert features["Packet Length Mean"] == 80.0
        assert features["_src_ip"] == "127.0.0.1"
