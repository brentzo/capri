"""Source-aware surface extraction (HC-AGENT-01 recon).

A developer runs Capri against an app whose source the operator has, so recon reads that
source to enumerate the complete HTTP surface - every registered route, method and
parameter, including the auth-gated ones a black-box crawl can never reach - rather than
guessing paths or crawling a running app. Extraction is deterministic: the same source
always yields the same surface, and a construct the extractor cannot resolve is recorded as
an explicit `unknown`, never guessed. A framework detector routes the source tree to the
matching adapter; `extract_surface` is the entry point.
"""
from harness.sourcemap.extract import extract_surface

__all__ = ["extract_surface"]
