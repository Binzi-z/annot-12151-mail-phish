"""SARIF 2.1.0 输出。

安全结论放在 runs[].results（eval.py 与 GitHub code scanning 都消费这里）；
动态派发降级诊断放在 runs[].invocations[].toolExecutionNotifications，
不会被当作漏洞计入 precision，也不会污染"幽灵告警"判定。
"""
from __future__ import annotations

import json

from .rules import RULE_VERSION
from . import ANALYZER_VERSION

LEVEL_BY_RULE = {
    "PY-CMD-001": "error",
    "PY-SQL-001": "error",
    "PY-PATH-001": "error",
    "PY-URL-001": "error",
    "PY-XML-001": "error",
    "PY-DYN-001": "warning",
}


def _rule_index():
    seen = {}
    rules = []
    for rid, level in LEVEL_BY_RULE.items():
        if rid in seen:
            continue
        seen[rid] = len(rules)
        rules.append({
            "id": rid,
            "name": rid.replace("-", "_"),
            "defaultConfiguration": {"level": level},
            "properties": {"precision": "high" if rid != "PY-DYN-001" else "medium"},
        })
    return rules, seen


def build_sarif(findings: list[dict], diagnostics: list[dict],
                parse_errors: list[dict], stats: dict) -> dict:
    rules, index = _rule_index()
    results = []
    for f in sorted(findings, key=lambda x: (x["file"], x["line"], x["rule_id"])):
        results.append({
            "ruleId": f["rule_id"],
            "ruleIndex": index[f["rule_id"]],
            "level": LEVEL_BY_RULE.get(f["rule_id"], "warning"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"].replace("\\", "/")},
                    "region": {"startLine": int(f["line"])},
                }
            }],
            "properties": {
                "cwe": f.get("cwe"),
                "kind": f.get("kind"),
                "sink": f.get("sink"),
                "taintSource": f.get("source"),
                "degraded": bool(f.get("degraded", False)),
            },
        })

    notifications = []
    for d in sorted(diagnostics, key=lambda x: (x["file"], x["line"])):
        notifications.append({
            "descriptor": {"id": "PY-DYN-DIAG"},
            "level": "warning",
            "message": {
                "text": (f"unresolved dispatch '{d['dotted']}' at {d['file']}:{d['line']} "
                         f"(sanitizer_shaped={d['sanitizer_shaped']}, policy={d['policy']})")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": d["file"].replace("\\", "/")},
                    "region": {"startLine": int(d["line"])},
                }
            }],
        })
    for pe in parse_errors:
        notifications.append({
            "descriptor": {"id": "PY-PARSE-ERROR"},
            "level": "error",
            "message": {"text": f"parse error in {pe['file']}: {pe['error']}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": pe["file"]}},
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "incremental-taint-analyzer",
                    "version": ANALYZER_VERSION,
                    "informationUri": "https://example.local/analyzer",
                    "rules": rules,
                    "properties": {"ruleVersion": RULE_VERSION, "scanStats": stats},
                }
            },
            "invocations": [{
                "executionSuccessful": not parse_errors,
                "toolExecutionNotifications": notifications,
            }],
            "results": results,
        }],
    }


def dump_sarif(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=1)
