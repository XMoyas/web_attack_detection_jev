from types import SimpleNamespace

from detector import WebAttackDetector, decide_action


def _answer(**kwargs):
    return SimpleNamespace(**kwargs)


def _fake_client(answers: dict):
    class FakeClient:
        def __init__(self):
            self.called = False
            self.last_state = None
            self.last_questions = None

        def system_one(self, state, questions):
            self.called = True
            self.last_state = state
            self.last_questions = questions
            return SimpleNamespace(answers=answers)

    return FakeClient()


def test_empty_payload_is_allowed_without_calling_jev():
    client = _fake_client({})
    detector = WebAttackDetector(client=client)

    result = detector.detect("   ")

    assert result.is_attack is False
    assert result.attack_type == "benign"
    assert result.action == "allow"
    assert client.called is False


def test_xss_payload_is_blocked():
    client = _fake_client(
        {
            "is_attack": _answer(noul=0.97),
            "attack_type": _answer(
                choice="xss",
                confidence=0.91,
                probabilities={"xss": 0.91, "benign": 0.02},
            ),
            "severity": _answer(score=2.8, confidence=0.8),
            "should_block": _answer(noul=0.94),
        }
    )
    detector = WebAttackDetector(client=client)

    result = detector.detect("<script>alert(1)</script>")

    assert result.is_attack is True
    assert result.attack_type == "xss"
    assert result.action == "block"
    assert result.attack_probability == 0.97
    assert 0.9 < result.attack_confidence <= 1.0


def test_benign_search_query_is_allowed():
    client = _fake_client(
        {
            "is_attack": _answer(noul=0.08),
            "attack_type": _answer(
                choice="benign",
                confidence=0.88,
                probabilities={"benign": 0.88, "xss": 0.04},
            ),
            "severity": _answer(score=1.05, confidence=0.9),
            "should_block": _answer(noul=0.04),
        }
    )
    detector = WebAttackDetector(client=client)

    result = detector.detect("red running shoes size 42")

    assert result.is_attack is False
    assert result.attack_type == "benign"
    assert result.action == "allow"


def test_ambiguous_signal_is_sent_to_review():
    client = _fake_client(
        {
            "is_attack": _answer(noul=0.52),
            "attack_type": _answer(
                choice="sql_injection",
                confidence=0.55,
                probabilities={"sql_injection": 0.55, "benign": 0.3},
            ),
            "severity": _answer(score=2.1, confidence=0.5),
            "should_block": _answer(noul=0.41),
        }
    )
    detector = WebAttackDetector(client=client)

    result = detector.detect("admin' --")

    assert result.action == "review"
    assert result.attack_type == "sql_injection"


def test_conflicting_high_attack_but_benign_label_is_review():
    assert (
        decide_action(
            is_attack_prob=0.9,
            attack_type="benign",
            should_block_prob=0.2,
        )
        == "review"
    )


def test_long_payload_is_truncated_before_jev():
    client = _fake_client(
        {
            "is_attack": _answer(noul=0.1),
            "attack_type": _answer(choice="benign", confidence=0.9, probabilities={}),
            "severity": _answer(score=1.0, confidence=0.9),
            "should_block": _answer(noul=0.01),
        }
    )
    detector = WebAttackDetector(client=client, max_payload_chars=32)
    payload = "A" * 200

    detector.detect(payload)

    sent = client.last_state["payload"]
    assert len(sent) == 32
    assert client.last_state["truncated"] is True
