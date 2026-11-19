"""增量污点分析器（CWE-78 等注入类规则）。

模块划分：
- rules:    规则注册表、污点类别、sink/sanitizer 定义、规则版本
- symbols:  AST 解析、符号表、函数指纹、跨文件符号解析
- taint:    过程内污点传播 + 跨函数摘要
- cache:    清单式缓存、缓存键因子、三类失效判定
- sarif:    SARIF 2.1.0 输出
- engine:   全量/增量分析编排、退出码
- replay:   40 条历史变更回放
"""

ANALYZER_VERSION = "1.0.0"
