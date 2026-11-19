"""符号表：AST 解析、模块/函数指纹、跨文件符号解析。

设计要点：
- 每个分析文件产出 FileModel：源码哈希（sha256）、模块名、导入表、函数表。
- 每个函数有两个指纹：
    sig_hash  = sha256(名字 + 参数形状 + 装饰器) —— "符号签名"，依赖失效判定用
    body_hash = sha256(规范化后的函数体 AST)     —— 签名没变但实现变了也要重扫
  fp = sha256(sig_hash + body_hash)，作为缓存清单里记录的符号指纹。
- 解析全部走 import 语句建立的别名表，不执行任何项目代码（无 import 副作用风险）。
"""
from __future__ import annotations

import ast
import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# 语言级内置名字：无 import 也可直接调用，归属到伪模块 builtins
BUILTIN_MODULE = "builtins"
BUILTIN_NAMES = {
    "open", "print", "len", "int", "float", "str", "bool", "bytes", "dict",
    "list", "tuple", "set", "frozenset", "range", "enumerate", "zip", "map",
    "filter", "sorted", "reversed", "sum", "min", "max", "abs", "any", "all",
    "isinstance", "issubclass", "getattr", "setattr", "hasattr", "format",
    "repr", "hash", "id", "type", "vars", "dir", "iter", "next", "input",
}


def _dump(node: ast.AST) -> str:
    """规范化 AST 文本：去掉行号/列号，使指纹只与语法结构有关。"""
    return ast.dump(node, annotate_fields=True, include_attributes=False)


@dataclass
class ImportBinding:
    raw_module: str          # import 语句里的原始模块名，如 xml.etree.ElementTree
    local_name: str          # 当前文件内的本地名（alias 或顶层包名）
    kind: str                # "module" | "symbol"
    symbol: Optional[str] = None  # kind == "symbol" 时的 from-import 符号名
    asname: bool = False     # module import 是否带 as 别名


@dataclass
class FunctionModel:
    name: str
    node: ast.FunctionDef
    qualname: str                       # 模块内限定名（本语料无嵌套类，等于 name）
    sig_hash: str
    body_hash: str
    fp: str
    args: list[str] = field(default_factory=list)
    # ---- 污点分析阶段填充 ----
    summary: Optional[dict] = None     # 见 taint.py 的摘要结构


@dataclass
class FileModel:
    relpath: str                        # 统一正斜杠
    module: str                         # 如 src.svc_00
    source: str
    source_hash: str
    tree: ast.Module
    imports: list[ImportBinding]
    functions: dict[str, FunctionModel]
    parse_error: Optional[str] = None


def _arg_shape(node: ast.FunctionDef) -> list:
    """参数形状：位置参数、*args、**kwargs、默认值数量、kwonly 数量。"""
    a = node.args
    pos = [p.arg for p in a.posonlyargs + a.args]
    return [
        pos,
        a.vararg.arg if a.vararg else None,
        a.kwarg.arg if a.kwarg else None,
        len(a.defaults),
        len(a.kwonlyargs),
        [d.id if isinstance(d, ast.Name) else _dump(d) for d in a.defaults],
        [d.id if isinstance(d, ast.Name) else _dump(d) for d in a.kw_defaults],
        [ast.dump(d) for d in node.decorator_list],
    ]


def build_function_model(node: ast.FunctionDef, module: str) -> FunctionModel:
    sig_blob = repr([node.name, _arg_shape(node)])
    sig_hash = sha256_text("sig:" + sig_blob)
    body_hash = sha256_text("body:" + _dump(node))
    fp = sha256_text("fp:" + sig_hash + body_hash)
    args = [p.arg for p in node.args.posonlyargs + node.args.args]
    return FunctionModel(
        name=node.name,
        node=node,
        qualname=f"{module}.{node.name}",
        sig_hash=sig_hash,
        body_hash=body_hash,
        fp=fp,
        args=args,
    )


def parse_file(relpath: str, source: str, package_prefix: Optional[str] = None) -> FileModel:
    rel_module = relpath[:-3].replace("/", ".") if relpath.endswith(".py") else relpath
    # 扫描根本身是一个包（目录名即包名，如 proj/、src/）时，模块的完整限定名
    # 必须带包前缀，否则 from proj.common import x 解析出的 proj.common 在
    # 符号表里找不到（表里只有 common），跨文件依赖会丢、反向失效就断了。
    module = f"{package_prefix}.{rel_module}" if package_prefix else rel_module
    try:
        tree = ast.parse(source, filename=relpath)
        parse_error = None
    except SyntaxError as exc:  # 解析失败：文件级致命错误，engine 按 exit code 2 处理
        tree = ast.Module(body=[], type_ignores=[])
        parse_error = f"{type(exc).__name__}: {exc.msg} (line {exc.lineno})"

    imports: list[ImportBinding] = []
    functions: dict[str, FunctionModel] = {}
    if parse_error is None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(ImportBinding(
                        raw_module=alias.name,
                        local_name=alias.asname or alias.name.split(".")[0],
                        kind="module",
                        asname=bool(alias.asname),
                    ))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    imports.append(ImportBinding(
                        raw_module=mod,
                        local_name=alias.asname or alias.name,
                        kind="symbol",
                        symbol=alias.name,
                    ))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 顶层函数与嵌套函数都登记；同名取外层（walk 顺序父先于子）
                functions.setdefault(node.name, build_function_model(node, module))

    return FileModel(
        relpath=relpath,
        module=module,
        source=source,
        source_hash=sha256_text(source),
        tree=tree,
        imports=imports,
        functions=functions,
        parse_error=parse_error,
    )


class SymbolTable:
    """全局符号表：知道每个模块对应哪个文件、每个本地名指向哪个 (模块, 符号)。"""

    def __init__(self, files: dict[str, FileModel], root_module: Optional[str] = None):
        self.files = files
        self.root_module = root_module  # 如 "src"；裸 import 同包模块时用于补全
        self.modules: dict[str, str] = {fm.module: rel for rel, fm in files.items()}

    def resolve(self, file: FileModel, dotted: str) -> tuple[Optional[str], Optional[str]]:
        """把文件内的点号名字解析为 (模块名, 函数名)。

        例：
            os.system                      -> ("os", "system")
            urllib.request.urlopen         -> ("urllib.request", "urlopen")
            _forward_5（from-import/本地） -> ("src.svc_02", "_forward_5")
        解析不到返回 (None, None) —— 由 taint.py 走动态派发降级。
        """
        parts = dotted.split(".")
        head, rest = parts[0], parts[1:]

        # 1) 本地函数定义优先（遮蔽导入）
        if head in file.functions and not rest:
            return file.module, head

        # 2) import 别名表——两遍扫描。
        #    同一文件里 `import urllib.request` 与 `import urllib.request as request`
        #    可共存：先做 from-import/symbol 精确匹配，再做 module 绑定，
        #    否则 request.urlopen 的模块名会被多拼一层。
        for imp in file.imports:
            if imp.kind == "symbol" and imp.local_name == head:
                raw = imp.raw_module
                # 包内裸模块 from common_util import x：符号表登记为 src.common_util，
                # 而 import 语句写的是裸名 common_util，需要用扫描根包名补全后才命中。
                if raw not in self.modules and self.root_module:
                    prefixed = f"{self.root_module}.{raw}"
                    if prefixed in self.modules:
                        raw = prefixed
                if rest:
                    return raw + "." + imp.symbol, ".".join(rest)
                return raw, imp.symbol
        for imp in file.imports:
            if imp.kind != "module" or imp.local_name != head:
                continue
            base = imp.raw_module
            if rest:
                if imp.asname:
                    # import a.b as c; c.x.y -> 本地名 c 即模块 a.b，
                    # 模块 = a.b + 属性链前缀，符号 = 属性链末段。
                    return ".".join([base] + rest[:-1]), rest[-1]
                # import a.b.c（local=a）；调用 a.b.c.<...>.sym：
                #   rest 里可能先重复 raw_module 的末段包名（Python 属性链
                #   从 local 逐级走回 raw 末段），再往后才是模块内符号。
                #   urllib.request.urlopen: base=urllib.request,
                #   rest=[request, urlopen] -> (urllib.request, urlopen)
                base_parts = base.split(".")
                tail = list(rest)
                if len(tail) >= 2 and tail[0] == base_parts[-1]:
                    tail = tail[1:]
                module = ".".join([base] + tail[:-1]) if len(tail) > 1 else base
                return module, tail[-1]
            return base, None

        # 3) Python 内置函数：无 import 的语言级名字（open/print/...）
        if not rest and head in BUILTIN_NAMES:
            return BUILTIN_MODULE, head

        # 4) 同包裸名兜底（语料里不应出现，保持保守）
        if self.root_module and not rest:
            cand = f"{self.root_module}.{head}"
            if cand in self.modules:
                return cand, None
        return None, None

    def get_function(self, module: str, symbol: str) -> Optional[FunctionModel]:
        rel = self.modules.get(module)
        if rel is None:
            return None
        fm = self.files[rel]
        return fm.functions.get(symbol)

    def project_modules(self) -> set[str]:
        return set(self.modules)
