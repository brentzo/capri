"""Bundled taxonomy reference for the HC-KB-01 validator.

Zero-dependency: this module hard-codes the identifier sets the knowledge base
cites, so the validator resolves taxonomy references offline (HC-KB-01 §9),
consistent with the egress-denied posture of the whole system.

Honesty rule: an identifier appears in a CONFIRMED set only when it is a real,
checked identifier in its catalog. Identifiers the author flagged `# verify`
but has not yet confirmed are deliberately LEFT OUT, so the validator reports
them as UNRESOLVED instead of silently blessing them. Resolving the KB's
`# verify` markers is exactly "move the id into the confirmed set once checked
against the upstream catalog" (or fix the card).

When the KB graduates to M2, replace these curated subsets with the full
upstream catalogs (a vendored CWE list, the ATT&CK/ATLAS STIX bundles, CAPEC);
the validator logic does not change.
"""

import re

# --- format patterns (always enforced) ---
RE = {
    "cwe":   re.compile(r"^CWE-\d+$"),
    "capec": re.compile(r"^CAPEC-\d+$"),
    "attack_technique": re.compile(r"^T\d{4}(?:\.\d{3})?$"),
    "attack_tactic":    re.compile(r"^TA\d{4}$"),
    "atlas": re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$"),
    # OWASP references are documentation pointers, validated by shape only.
    "owasp": re.compile(
        r"^(WSTG-[A-Z]+-\d{2,3}|API\d:20\d{2}|LLM\d{2}:20\d{2}|M\d:20\d{2})"
        r"(\s*\([^)]*\))?$"
    ),
}

# --- CONFIRMED identifier sets (real, checked) ---

# Every CWE the KB cites; all are real CWE weakness ids.
CWE = {
    "CWE-16", "CWE-22", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-88",
    "CWE-89", "CWE-94", "CWE-121", "CWE-122", "CWE-125", "CWE-134", "CWE-190",
    "CWE-200", "CWE-212", "CWE-213", "CWE-226", "CWE-269", "CWE-284", "CWE-285",
    "CWE-306", "CWE-307", "CWE-311", "CWE-312", "CWE-319", "CWE-340", "CWE-345",
    "CWE-347", "CWE-352", "CWE-354", "CWE-362", "CWE-367", "CWE-384", "CWE-400",
    "CWE-405", "CWE-407", "CWE-409", "CWE-416", "CWE-427", "CWE-441", "CWE-444",
    "CWE-459", "CWE-476", "CWE-488", "CWE-494", "CWE-502", "CWE-524", "CWE-530",
    "CWE-532", "CWE-601", "CWE-611", "CWE-639", "CWE-693", "CWE-749", "CWE-770",
    "CWE-776", "CWE-787", "CWE-789", "CWE-798", "CWE-829", "CWE-843", "CWE-862",
    "CWE-915", "CWE-918", "CWE-922", "CWE-926", "CWE-927", "CWE-939", "CWE-942",
    "CWE-1021", "CWE-1104", "CWE-1321", "CWE-1333", "CWE-1336", "CWE-1427",
}

# MITRE ATT&CK Enterprise techniques/tactics the KB cites; all real.
ATTACK = {
    "TA0001",
    "T1021", "T1059", "T1059.007", "T1078.004", "T1098", "T1110.004",
    "T1190", "T1195", "T1195.001", "T1195.002", "T1203", "T1213", "T1485",
    "T1499", "T1499.001", "T1499.003", "T1499.004", "T1530", "T1539",
    "T1550.001", "T1552", "T1552.001", "T1552.005", "T1565.001", "T1610",
    "T1611",
}

# MITRE ATLAS techniques (confirmed against ATLAS v4.9.0). Base techniques are
# used; prompt-injection direct/indirect sub-technique suffixes were not
# confirmed, so the injection cards cite the base AML.T0051.
ATLAS = {
    "AML.T0051",   # LLM Prompt Injection
    "AML.T0053",   # LLM Plugin Compromise (a.k.a. AI agent tool invocation)
    "AML.T0054",   # LLM Jailbreak
    "AML.T0057",   # LLM Data Leakage
}

CAPEC = {"CAPEC-66"}

# Severity bands and success-signal types reused by the validator.
SEVERITIES = {"info", "low", "medium", "high", "critical"}
SIGNAL_TYPES = {
    "status_match", "content_match", "response_diff", "differential",
    "timing_oracle", "state_change", "oob_callback",
}
KB_CLASSES = {
    "WEB", "CLIENT", "AILLM", "CLOUD", "SUPPLY", "RPC", "DOS", "DATA",
    "BIN", "MOBILE",
}

# In-sandbox collaborators an oob_callback may terminate at (HC-KB-01 §5).
IN_RANGE_COLLABORATORS = {"range-oob"}
# An external-looking host in a collaborator/url position is a hard error.
RE_EXTERNAL_HOST = re.compile(r"\b[\w.-]+\.(?:com|net|org|io|dev|ai|cloud)\b", re.I)
RE_RANGE_HOST = re.compile(r"\.range\.local$|^range-[\w-]+$", re.I)


def resolve(kind, ident):
    """Return (ok_format, resolved) for an identifier of a given kind."""
    ident = ident.strip()
    if kind == "cwe":
        return bool(RE["cwe"].match(ident)), ident in CWE
    if kind == "capec":
        return bool(RE["capec"].match(ident)), ident in CAPEC
    if kind == "atlas":
        return bool(RE["atlas"].match(ident)), ident in ATLAS
    if kind == "owasp":
        return bool(RE["owasp"].match(ident)), bool(RE["owasp"].match(ident))
    if kind == "attack_technique":
        return bool(RE["attack_technique"].match(ident)), ident in ATTACK
    if kind == "attack_tactic":
        return bool(RE["attack_tactic"].match(ident)), ident in ATTACK
    return False, False
