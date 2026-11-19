"""全量/增量分析编排与 CI 退出码。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from . import ANALYZER_VERSION
from .cache import CacheEntry, CacheManifest, compute_cache_key, compute_entry_set_hash
from .rules import RULE_VERSION
from .sarif import build_sarif, dump_sarif
from .symbols import FileModel, SymbolTable, parse_file
from .taint import POLICY_FAIL_CLOSED, analyze_file

# CI 退出码约定
EXIT_CLEAN = 0
EXIT_FINDINGS = 1       # 发现安全问题
EXIT_FATAL = 2          # 解析错误等致命问题（结果不完整，不应放行）
EXIT_UNRESOLVED = 3     # 无 error 级发现，但存在未解析动态派发诊断
EXIT_CACHE_FORCED_FULL = 4  # 缓存不可信触发了强制全量（供 CI 观测，不代表失败）


@dataclass
class ScanResult:
    sarif: dict
    findings: list[dict]
    diagnostics: list[dict]
    parse_errors: list[dict]
    stats: dict
    reasons: list[str] = field(default_factory=list)
    forced_full: bool = False
    exit_code: int = 0


def discover_python_files(root: str) -> list[str]:
    rels = []
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", ".incremental-cache"}]
        for n in names:
            if n.endswith(".py"):
                full = os.path.join(dirpath, n)
                rels.append(os.path.relpath(full, root).replace("\\", "/"))
    return sorted(rels)


def _detect_root_module(rels: list[str]) -> Optional[str]:
    tops = {r.split("/")[0] for r in rels if "/" in r}
    if len(tops) == 1:
        top = next(iter(tops))
        if f"{top}/__init__.py" in rels:
            return top
    return None


def load_workspace(root: str) -> tuple[dict[str, FileModel], SymbolTable]:
    rels = discover_python_files(root)
    # 扫描根是包（含 __init__.py）时，目录名就是 import 用的包名前缀
    root_base = os.path.basename(os.path.normpath(root))
    package_prefix = root_base if "__init__.py" in rels else None
    files: dict[str, FileModel] = {}
    for rel in rels:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            source = fh.read()
        files[rel] = parse_file(rel, source, package_prefix=package_prefix)
    root_module = _detect_root_module(rels)
    if package_prefix:
        root_module = package_prefix
    return files, SymbolTable(files, root_module=root_module)


def run_scan(root: str, cache_dir: Optional[str] = None, *,
             full: bool = False, policy: str = POLICY_FAIL_CLOSED,
             quiet_cache_miss: bool = False,
             uri_prefix: Optional[str] = None) -> ScanResult:
    files, symbols = load_workspace(root)
    cache_dir = cache_dir or os.path.join(root, ".incremental-cache")
    os.makedirs(cache_dir, exist_ok=True)
    manifest = CacheManifest(cache_dir, policy)

    reasons: list[str] = []
    forced_full = full
    if full:
        reasons.append("manual --full: cache bypassed")
        ok = manifest.load()
        if not ok:
            reasons.append("(also: existing manifest unusable, dropped)")
        manifest.entries.clear()
    else:
        ok = manifest.load()
        if not ok:
            forced_full = True
            reasons.append(
                f"cache invalidation (factor 3 / integrity): "
                f"{manifest.invalidation_reason} -> full reanalysis")
            manifest.entries.clear()

    stale: set[str] = set()
    if not forced_full:
        stale, inv_reasons = manifest.invalidate_plan(files, symbols)
        reasons.extend(inv_reasons)
    else:
        stale = set(files)

    all_findings: list[dict] = []
    all_diags: list[dict] = []
    parse_errors: list[dict] = []
    reused, rescanned = 0, 0

    for rel, fm in sorted(files.items()):
        if fm.parse_error:
            parse_errors.append({"file": rel, "error": fm.parse_error})
            # 解析错误的文件绝不复用旧结论
            manifest.entries.pop(rel, None)
            continue
        if rel in stale or rel not in manifest.entries:
            result = analyze_file(symbols, fm, policy)
            key = compute_cache_key(fm, result["dependencies"], policy)
            manifest.update(rel, CacheEntry(
                relpath=rel,
                cache_key=key,
                source_hash=fm.source_hash,
                rule_version=RULE_VERSION,
                analyzer_version=ANALYZER_VERSION,
                policy=policy,
                entry_set_hash=compute_entry_set_hash(fm),
                dependencies=result["dependencies"],
                findings=result["findings"],
                diagnostics=result["diagnostics"],
                parse_error=None,
            ))
            all_findings.extend(result["findings"])
            all_diags.extend(result["diagnostics"])
            rescanned += 1
        else:
            entry = manifest.entries[rel]
            # 双保险：即使 invalidate 逻辑漏判，命中时再验一次完整缓存键
            expected = compute_cache_key(fm, entry.dependencies, policy)
            if expected != entry.cache_key:
                reasons.append(f"{rel}: cache_key mismatch on read, rescan")
                result = analyze_file(symbols, fm, policy)
                entry = CacheEntry(
                    relpath=rel, cache_key=expected, source_hash=fm.source_hash,
                    rule_version=RULE_VERSION, analyzer_version=ANALYZER_VERSION,
                    policy=policy, entry_set_hash=compute_entry_set_hash(fm),
                    dependencies=result["dependencies"], findings=result["findings"],
                    diagnostics=result["diagnostics"], parse_error=None,
                )
                manifest.update(rel, entry)
                all_findings.extend(result["findings"])
                all_diags.extend(result["diagnostics"])
                rescanned += 1
            else:
                all_findings.extend(entry.findings)
                all_diags.extend(entry.diagnostics)
                reused += 1

    # 缓存里残留、但工作区已不存在的文件：invalidate_plan 已剔除；
    # 这里再按结果集与当前文件集合做一次"幽灵告警"兜底过滤。
    live = set(files)
    before = len(all_findings)
    all_findings = [f for f in all_findings if f["file"] in live]
    if len(all_findings) != before:
        reasons.append("ghost guard removed findings belonging to deleted files")

    manifest.save()

    # 去重（不同文件的缓存条目理论上不会重复，兜底）
    dedup = {}
    for f in all_findings:
        dedup[(f["file"], f["line"], f["rule_id"])] = f
    all_findings = sorted(dedup.values(), key=lambda x: (x["file"], x["line"], x["rule_id"]))

    stats = {
        "filesTotal": len(files),
        "filesRescanned": rescanned,
        "filesReusedFromCache": reused,
        "findings": len(all_findings),
        "unresolvedDispatch": len(all_diags),
        "ruleVersion": RULE_VERSION,
        "analyzerVersion": ANALYZER_VERSION,
        "mode": "full" if forced_full or reused == 0 else "incremental",
    }
    # SARIF URI 可加仓库根前缀（扫描根是子目录时与 labels/代码平台路径对齐）；
    # 缓存内部仍存扫描根相对路径，前缀只影响报告层，故用副本避免污染缓存对象。
    if uri_prefix:
        pfx = uri_prefix.rstrip("/") + "/"
        all_findings = [dict(f, file=pfx + f["file"]) for f in all_findings]
        all_diags = [dict(d, file=pfx + d["file"]) for d in all_diags]
        parse_errors = [dict(pe, file=pfx + pe["file"]) for pe in parse_errors]
    sarif = build_sarif(all_findings, all_diags, parse_errors, stats)

    exit_code = EXIT_CLEAN
    if parse_errors:
        exit_code = EXIT_FATAL
    elif all_findings:
        exit_code = EXIT_FINDINGS
    elif all_diags:
        exit_code = EXIT_UNRESOLVED
    # 只有"非预期的强制全量"（缓存损坏/版本失效等）才给观测码 4；
    # 用户显式 --full 属于正常操作，退出码只反映安全结论本身。
    if forced_full and not full and exit_code == EXIT_CLEAN and not quiet_cache_miss:
        exit_code = EXIT_CACHE_FORCED_FULL

    return ScanResult(
        sarif=sarif, findings=all_findings, diagnostics=all_diags,
        parse_errors=parse_errors, stats=stats, reasons=reasons,
        forced_full=forced_full, exit_code=exit_code,
    )


def render_report(result: ScanResult) -> str:
    return dump_sarif(result.sarif)
