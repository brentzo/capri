"""Sandbox substrate backends (HC-SUB-01 §10).

`Sandbox` is the backend-agnostic interface the control loop drives; `PassiveOnlySandbox`
is the safe default that proves nothing; `DockerSandbox` is the first real backend.
"""
from harness.sandbox.base import (
    PassiveOnlySandbox,
    Sandbox,
    SandboxError,
    guard_proof_result,
)

__all__ = ["Sandbox", "PassiveOnlySandbox", "SandboxError", "guard_proof_result"]
