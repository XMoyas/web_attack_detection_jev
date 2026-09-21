from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from dotenv import load_dotenv
from typesafe_sdk import TypeSafeClient

from config import (
    ATTACK_THRESHOLD,
    BLOCK_THRESHOLD,
    DEFAULT_MODEL,
    MAX_PAYLOAD_CHARS,
    REVIEW_THRESHOLD,
)
from questions import build_questions

load_dotenv()

Action = Literal["allow", "review", "block"]


@dataclass
class DetectionResult:
    payload: str
    is_attack: bool
    attack_type: str
    attack_probability: float
    attack_confidence: float
    severity: float
    should_block: float
    action: Action
    probabilities: dict[str, float] = field(default_factory=dict)
    truncated: bool = False
    content_type: str | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def decide_action(
    is_attack_prob: float,
    attack_type: str,
    should_block_prob: float,
) -> Action:
    if is_attack_prob >= ATTACK_THRESHOLD and attack_type != "benign":
        if should_block_prob >= BLOCK_THRESHOLD:
            return "block"
        return "block" if should_block_prob >= REVIEW_THRESHOLD else "review"

    if is_attack_prob >= ATTACK_THRESHOLD and attack_type == "benign":
        return "review"

    if is_attack_prob >= REVIEW_THRESHOLD or (
        attack_type != "benign" and is_attack_prob >= REVIEW_THRESHOLD
    ):
        return "review"

    return "allow"


def _empty_result(
    payload: str,
    content_type: str | None,
    path: str | None,
) -> DetectionResult:
    return DetectionResult(
        payload=payload,
        is_attack=False,
        attack_type="benign",
        attack_probability=0.0,
        attack_confidence=1.0,
        severity=0.0,
        should_block=0.0,
        action="allow",
        probabilities={"benign": 1.0},
        truncated=False,
        content_type=content_type,
        path=path,
    )


class WebAttackDetector:
    def __init__(
        self,
        client: Any | None = None,
        *,
        max_payload_chars: int = MAX_PAYLOAD_CHARS,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._model = model
        self.max_payload_chars = max_payload_chars

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = TypeSafeClient(model=self._model)
        return self._client

    def detect(
        self,
        payload: str,
        content_type: str | None = None,
        path: str | None = None,
    ) -> DetectionResult:
        if payload is None or not str(payload).strip():
            return _empty_result(payload or "", content_type, path)

        truncated = len(payload) > self.max_payload_chars
        sent_payload = payload[: self.max_payload_chars]
        state = {
            "task": "web attack detection",
            "payload": sent_payload,
            "content_type": content_type,
            "path": path,
            "original_length": len(payload),
            "truncated": truncated,
        }
        response = self.client.system_one(state=state, questions=build_questions())
        answers = response.answers

        is_attack_prob = float(answers["is_attack"].noul)
        attack_type = str(answers["attack_type"].choice)
        attack_confidence = float(getattr(answers["attack_type"], "confidence", 0.0) or 0.0)
        probabilities = dict(getattr(answers["attack_type"], "probabilities", {}) or {})
        severity = float(answers["severity"].score)
        should_block_prob = float(answers["should_block"].noul)
        action = decide_action(is_attack_prob, attack_type, should_block_prob)
        is_attack = attack_type != "benign" and is_attack_prob >= ATTACK_THRESHOLD

        return DetectionResult(
            payload=payload,
            is_attack=is_attack,
            attack_type=attack_type,
            attack_probability=round(is_attack_prob, 4),
            attack_confidence=round(attack_confidence, 4),
            severity=round(severity, 4),
            should_block=round(should_block_prob, 4),
            action=action,
            probabilities={k: round(float(v), 4) for k, v in probabilities.items()},
            truncated=truncated,
            content_type=content_type,
            path=path,
        )
