from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import api


class FakeDetector:
    def detect(self, payload, content_type=None, path=None):
        is_xss = payload.startswith("<script")
        return SimpleNamespace(
            to_dict=lambda: {
                "payload": payload,
                "is_attack": is_xss,
                "attack_type": "xss" if is_xss else "benign",
                "attack_probability": 0.96 if is_xss else 0.05,
                "attack_confidence": 0.9,
                "severity": 3.0 if is_xss else 1.0,
                "should_block": 0.95 if is_xss else 0.02,
                "action": "block" if is_xss else "allow",
                "probabilities": {"xss": 0.9} if is_xss else {"benign": 0.9},
                "truncated": False,
                "content_type": content_type,
                "path": path,
            }
        )


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(api, "get_detector", lambda: FakeDetector())
    return TestClient(api.app)


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_detect_endpoint_blocks_xss(client):
    res = client.post("/detect", json={"payload": "<script>alert(1)</script>"})
    assert res.status_code == 200
    body = res.json()
    assert body["is_attack"] is True
    assert body["attack_type"] == "xss"
    assert body["action"] == "block"


def test_detect_endpoint_requires_payload(client):
    res = client.post("/detect", json={})
    assert res.status_code == 422
