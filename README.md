# 运单服务的增量分析缓存

## 现状

`baseline/scan.py` 是现在用的做法：只要出现 execute/open/system/urlopen/etree.parse/iterparse 或硬编码 AK 就报。
召回够，但误报高得没法用——`eval.py` 能算出具体数字。

## 语料

- `src/`：6 个模块，7 个真漏洞、5 个假漏洞（形状一样但中途过了 sanitizer）
- `labels.json`：真漏洞的文件、行号与传播路径
- `eval.py`：拿你的结果和 labels 对比，输出召回/误报

## 跑法

```
python baseline/scan.py > findings.json
python eval.py findings.json
python -m pytest tests -q
```

## 增量分析器（incremental/）

在基线之上实现的 AST 污点分析 + 三因子增量缓存，设计细节见
[`docs/incremental-analyzer.md`](docs/incremental-analyzer.md)。

```
# 全量（SARIF 输出，--uri-prefix 让 artifact 路径与 labels 的 src/ 前缀对齐）
python -m incremental.cli scan --root src --full --sarif out.sarif --uri-prefix src
python eval.py out.sarif

# 增量（延续 src/.incremental-cache，--explain 打印每个文件的命中/失效原因）
python -m incremental.cli scan --root src --sarif out.sarif --uri-prefix src --explain

# 40 条历史变更回放：增量必须与全量逐结论一致且无幽灵告警
python -m incremental.replay --root src
```

缓存三因子：源文件哈希、被依赖符号指纹（签名+函数体）、规则版本；公共工具函数
变更通过反向依赖闭包让所有调用方一起重扫。CI 退出码 0/1/2/3/4 的含义见文档第 7 节。

