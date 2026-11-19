"""增量缓存：按文件哈希 + 符号表依赖 + 规则版本构建清单。

缓存键（每条 entry 独立计算，因子全部写进 entry，命中判定 = 逐因子比对）：

    cache_key = sha256(
        RULE_VERSION                       # 因子 3：分析规则版本
      + analyzer_version                   #         分析器实现版本（兜底）
      + source_hash                        # 因子 1：源文件内容哈希（sha256）
      + root_relpath                       #         文件在扫描根中的身份（防路径混淆）
      + sorted(dep: module.symbol@fp)      # 因子 2：被依赖符号的指纹（含签名+函数体）
      + entry_set_hash                     #         入口函数集合（防止入口增删漏扫）
      + policy                             #         降级策略（fail-closed / quarantine）
    )

三类失效的落地方式：
  1. 源文件变了      -> 重新哈希后 source_hash 不一致，entry 失效。
  2. 依赖符号签名变了 -> 依赖里记录的 fp 与当前符号表重算的 fp 不一致，entry 失效；
                        且失效按反向依赖闭包传播（公共工具一改，所有调用方一起重扫）。
  3. 规则版本变了    -> manifest.rule_version 与当前 RULE_VERSION 不等，整盘作废。

直接放弃缓存、强制全量的改动（见 docs/incremental-analyzer.md）：
  - 规则/分析器版本变更、manifest 损坏/截断/JSON 不合法
  - 扫描根路径变化、文件被删除后又以同名复活（身份不可信）
  - 解析错误（SyntaxError）的文件
  - 依赖符号在当前符号表中解析不到（定义被删/改名），无法验证 fp
  - --full 显式要求
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .rules import RULE_VERSION
from .symbols import FileModel, SymbolTable
from . import ANALYZER_VERSION

MANIFEST_NAME = "incremental-cache.json"
MANIFEST_SCHEMA = 1


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class CacheEntry:
    relpath: str
    cache_key: str
    source_hash: str
    rule_version: str
    analyzer_version: str
    policy: str
    entry_set_hash: str
    dependencies: list[dict]          # [{module, symbol, fp}]
    findings: list[dict]
    diagnostics: list[dict]
    parse_error: Optional[str]

    def to_json(self) -> dict:
        return self.__dict__

    @classmethod
    def from_json(cls, doc: dict) -> "CacheEntry":
        return cls(**doc)


def compute_entry_set_hash(file: FileModel) -> str:
    from .taint import find_entries
    names = sorted(fn.name for fn in find_entries(file))
    return _h("entries:" + "|".join(names))


def compute_cache_key(file: FileModel, dependencies: list[dict], policy: str) -> str:
    dep_blob = "|".join(
        f"{d['module']}.{d['symbol']}@{d['fp']}" for d in sorted(
            dependencies, key=lambda d: (d["module"], d["symbol"]))
    )
    raw = "\x1f".join([
        RULE_VERSION,
        ANALYZER_VERSION,
        file.source_hash,
        file.relpath,
        dep_blob,
        compute_entry_set_hash(file),
        policy,
    ])
    return _h("ck:" + raw)


class CacheManifest:
    def __init__(self, root: str, policy: str):
        self.root = root
        self.policy = policy
        self.path = os.path.join(root, MANIFEST_NAME)
        self.rule_version = RULE_VERSION
        self.analyzer_version = ANALYZER_VERSION
        self.entries: dict[str, CacheEntry] = {}
        self.corrupt = False
        self.invalidation_reason: Optional[str] = None

    # ---------------------------------------------------------- 持久化
    def load(self) -> bool:
        if not os.path.exists(self.path):
            self.invalidation_reason = "no manifest yet (cold start)"
            return True
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if doc.get("schema") != MANIFEST_SCHEMA:
                self.corrupt = True
                self.invalidation_reason = "manifest schema mismatch"
                return False
            if doc.get("rule_version") != RULE_VERSION:
                # 规则版本失效：整盘作废（因子 3）
                self.invalidation_reason = (
                    f"rule version changed: cached={doc.get('rule_version')} "
                    f"current={RULE_VERSION}")
                return False
            if doc.get("analyzer_version") != ANALYZER_VERSION:
                self.invalidation_reason = (
                    f"analyzer version changed: cached={doc.get('analyzer_version')} "
                    f"current={ANALYZER_VERSION}")
                return False
            self.entries = {
                rel: CacheEntry.from_json(d) for rel, d in doc["entries"].items()
            }
            self.invalidation_reason = None
            return True
        except (json.JSONDecodeError, KeyError, TypeError, OSError):
            self.corrupt = True
            self.invalidation_reason = "manifest corrupt/unreadable"
            return False

    def save(self) -> None:
        doc = {
            "schema": MANIFEST_SCHEMA,
            "rule_version": RULE_VERSION,
            "analyzer_version": ANALYZER_VERSION,
            "policy": self.policy,
            "entries": {rel: e.to_json() for rel, e in sorted(self.entries.items())},
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)  # 原子替换，防止半截清单被下次读到

    # ---------------------------------------------------------- 失效判定
    def invalidate_plan(self, files: dict[str, FileModel],
                        symbols: SymbolTable) -> tuple[set[str], list[str]]:
        """返回 (必须重扫的文件集合, 失效原因列表)。

        失效沿反向依赖传播：A 依赖符号 f，f 的指纹变了 -> A 重扫；
        A 重扫后其自身结论变化，依赖 A 的文件同样重扫（定点收敛）。
        """
        reasons: list[str] = []
        stale: set[str] = set()
        current_rels = set(files)

        # 缓存里有、当前工作区没有（删除/重命名）——直接丢弃，不进入结果
        for rel in list(self.entries):
            if rel not in current_rels:
                self.entries.pop(rel, None)
                reasons.append(f"{rel}: removed from workspace, cache entry dropped")

        # 第一遍：逐文件本地因子判定
        for rel, fm in files.items():
            entry = self.entries.get(rel)
            if entry is None:
                stale.add(rel)
                reasons.append(f"{rel}: no cache entry (first scan or new file)")
                continue
            if entry.source_hash != fm.source_hash:
                stale.add(rel)
                reasons.append(f"{rel}: source hash changed (factor 1)")
                continue
            if entry.policy != self.policy:
                stale.add(rel)
                reasons.append(f"{rel}: degradation policy changed")
                continue
            if entry.entry_set_hash != compute_entry_set_hash(fm):
                stale.add(rel)
                reasons.append(f"{rel}: entry-point set changed")
                continue
            if fm.parse_error:
                stale.add(rel)
                reasons.append(f"{rel}: parse error, cache unusable")
                continue
            # 依赖符号逐个验证指纹（因子 2）
            for dep in entry.dependencies:
                fn = symbols.get_function(dep["module"], dep["symbol"])
                if fn is None:
                    stale.add(rel)
                    reasons.append(
                        f"{rel}: dependency {dep['module']}.{dep['symbol']} "
                        f"unresolvable, abandon cache -> full reanalysis")
                    break
                if fn.fp != dep["fp"]:
                    stale.add(rel)
                    reasons.append(
                        f"{rel}: symbol signature/fingerprint changed for "
                        f"{dep['module']}.{dep['symbol']} (factor 2)")
                    break

        # 第二遍：反向依赖闭包。被重扫文件里定义的符号，其调用方也要重扫——
        # 即使调用方文件本身的 source_hash 没变（这正是事故里漏掉的场景）。
        changed = set(stale)
        while True:
            newly: set[str] = set()
            for rel, entry in self.entries.items():
                if rel in stale:
                    continue
                for dep in entry.dependencies:
                    owner_rel = symbols.modules.get(dep["module"])
                    if owner_rel in changed:
                        newly.add(rel)
                        reasons.append(
                            f"{rel}: reverse-dependency closure via {dep['module']}.{dep['symbol']}")
                        break
            if not newly:
                break
            stale |= newly
            changed |= newly

        return stale, reasons

    def update(self, rel: str, entry: CacheEntry) -> None:
        self.entries[rel] = entry
