from typing import Annotated

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from keepsense.services import facts

router = APIRouter(tags=["compare"])

# ponytail: 10k chars is a guess, tune to the LLM context window in step 6
Text = Annotated[str, Field(max_length=10_000, pattern=r"\S")]


class CompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    original: Text
    rewritten: Text


class CompareResponse(BaseModel):
    identical: bool
    passed: bool
    issues: list[facts.Issue]


@router.post("/compare")
def compare(request: CompareRequest) -> CompareResponse:
    issues = facts.compare(request.original, request.rewritten)
    return CompareResponse(
        identical=request.original == request.rewritten,
        passed=not any(issue.severity == "error" for issue in issues),
        issues=issues,
    )
