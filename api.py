from __future__ import annotations

from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from typesafe_sdk import (
    TypeSafeAuthenticationError,
    TypeSafeError,
    TypeSafeRateLimitError,
)

from detector import WebAttackDetector

load_dotenv()

_detector: WebAttackDetector | None = None


def get_detector() -> WebAttackDetector:
    global _detector
    if _detector is None:
        _detector = WebAttackDetector()
    return _detector


app = FastAPI(
    title="Web Attack Detector",
    description="JEV-based detector for XSS, SQL injection, XXE and other common web attacks.",
    version="1.0.0",
)


class DetectRequest(BaseModel):
    payload: str = Field(..., description="Raw request body, query, header value, or XML/JSON snippet")
    content_type: str | None = Field(default=None, description="Optional Content-Type of the original request")
    path: str | None = Field(default=None, description="Optional URL path, e.g. /search")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "payload": "<script>alert(1)</script>",
                    "content_type": "text/html",
                    "path": "/comment",
                }
            ]
        }
    }


class BatchDetectRequest(BaseModel):
    payloads: list[str] = Field(..., min_length=1, max_length=50)


def _run_detect(payload: str, content_type: str | None = None, path: str | None = None) -> dict[str, Any]:
    try:
        return get_detector().detect(payload, content_type=content_type, path=path).to_dict()
    except TypeSafeAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=f"JEV authentication failed: {exc}") from exc
    except TypeSafeRateLimitError as exc:
        raise HTTPException(status_code=429, detail=f"JEV rate limited: {exc}") from exc
    except TypeSafeError as exc:
        raise HTTPException(status_code=502, detail=f"JEV call failed: {exc}") from exc


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model": "jev"}


@app.post("/detect")
def detect(req: DetectRequest) -> dict[str, Any]:
    return _run_detect(req.payload, req.content_type, req.path)


@app.post("/detect/batch")
def detect_batch(req: BatchDetectRequest) -> dict[str, Any]:
    results = [_run_detect(payload) for payload in req.payloads]
    return {"count": len(results), "results": results}
