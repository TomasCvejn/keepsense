from typing import Annotated

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI()

# ponytail: 10k chars is a guess, tune to the LLM context window in step 6
Text = Annotated[str, Field(max_length=10_000, pattern=r"\S")]


class CompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    original: Text
    rewritten: Text


class CompareResponse(BaseModel):
    identical: bool


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/compare")
def compare(request: CompareRequest) -> CompareResponse:
    return CompareResponse(identical=request.original == request.rewritten)
