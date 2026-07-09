"""builtin:secret_check — redacted secret scan. NEVER emits an unredacted value."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from taar.classification import escalate, find_secret_matches, is_placeholder, redact
from taar.context import ExecutionContext
from taar.evidence import read_evidence, validate_evidence_hash
from taar.models import BuiltinResult, ClassificationLevel, Finding
from taar.checks._common import TEXT_SUFFIXES, iter_text_files as _iter_text_files, make_finding as _finding

def secret_check(ctx: ExecutionContext) -> BuiltinResult:
    """Detect likely exposed secrets with mandatory redaction."""
    findings: list[Finding] = []
    ignored: list[dict] = []
    classification = ClassificationLevel.OPEN

    for path in _iter_text_files(ctx.repo_root):
        if ctx.config.automation_root in path.parents:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern_name, value in find_secret_matches(line):
                if is_placeholder(line):
                    findings.append(
                        _finding("info", f"Placeholder {pattern_name} pattern (redacted: {redact(value)})",
                                 str(path.relative_to(ctx.repo_root)), line_no)
                    )
                    continue
                severity = "critical" if pattern_name in ("private_key", "openai_style_key", "github_token", "github_pat", "aws_access_key") else "high"
                if pattern_name == "private_key":
                    message = f"Private key material detected (type header only; value withheld)"
                else:
                    message = f"Possible {pattern_name}: {redact(value)}"
                findings.append(_finding(severity, message, str(path.relative_to(ctx.repo_root)), line_no))
                classification = escalate(classification, ClassificationLevel.SECRET)

    return BuiltinResult(0, f"secret scan: {len(findings)} finding(s)", "", findings, ignored, [], classification)
