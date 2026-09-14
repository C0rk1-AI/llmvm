# LLMVM — 面向 LLM 静态分析的代码虚拟化保护器

与常见壳/VM 保护器（对抗人工逆向者）不同，LLMVM 的对抗目标是 **LLM + 反编译器（IDA/Hex-Rays）的静态分析**：让 LLM 在分析被保护程序时被诱饵带偏、得出错误结论、或因上下文预算/成本墙而无法解读真实代码。设计文档见 [DESIGN.md](DESIGN.md)（失败模式 → 机制映射表）。

```
vm_targets.c (subset-C) ──vmc.py──▶ protected.c (VM解释器+wrapper+诱饵) ──cl──▶ exe ──pepolish──▶ final.exe
同样逻辑的原生 C       ─────────────────────────────────────────────────────cl──▶ plain.exe (对照组)
```

正确性判据：`plain.exe` 与 `final.exe` stdout 逐字节一致（run_demo / run_selftest 自动 diff）。

## 环境要求

- Windows x64，VS2017 (MSVC 14.16) —— 默认路径 `D:\VS17`，其它路径设置环境变量
  `LLMVM_VCVARS` 指向你的 `vcvars64.bat`
- Python 3.10+（纯标准库，无第三方依赖）
- （可选）IDA Pro 9.1 + idalib，用于复现验证报告：
  `pip install "C:\Program Files\IDA Professional 9.1\idalib\python"` 然后
  `python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"`

## 快速开始

```bash
# 1. 演示：构建 plain 对照组 + VM 保护版（含 pepolish + 假导出），运行并 diff
python run_demo.py

# 2. 语义等价回归：随机种子批量构建 VM/原生两版，输出必须逐字节一致
python run_selftest.py

# 3. handler 模板恒等式测试（30 个多态模板 × 大量随机输入，0 失配为过）
python tools_tpl_test.py

# 4. 对任意 exe 生成 IDA 分析报告（复现本文档中的验证实验）
python tools_ida.py evidence/sample_alpha.exe my_report.txt 14

# 5. 折叠地面真值密钥并校验构建确定性（seed 见 evidence/seed.txt）
python evidence/fold_true_key.py

# 6. v3 内层程序差分审计：真实构建的每个内层程序 vs 原生语义（0 失配为过）
python evidence/inner_audit.py <seed>
```

完整验证实验（本人 idalib 分析 + 三组不知情盲测 + 密钥核验）见 [REPORT.md](REPORT.md)，
各轮盲测样本、地面真值与复核脚本存档于 [evidence/](evidence/)。
v3（VM-in-VM + 反规范化 + 公式变体 + 元数据关闭）的机制见 [DESIGN.md](DESIGN.md) §2b，
复测见 [REPORT.md](REPORT.md) §6。

## 保护自己的代码

1. 把要保护的函数写进一个 subset-C 文件（支持：int8..int64/uint8..uint64、指针、
   一维数组、if/else、for/while、break/continue、算术/位/比较运算、函数互调；
   不支持：struct、浮点、多维数组、递归、变参、库函数直接调用——host 函数由
   `host_config.py` 显式注册，如 puts/printf）。参考 `demo/vm_targets.c`、
   `tests/selftest_targets.c`。
2. 入口 main 写在单独文件（`--main`），其中对保护函数的调用会被替换成 VM wrapper。
3. 生成 + 编译 + 伪装：

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # vmlib/build.py build_exe() 封装了这一步
python pepolish.py final.exe      # 节名伪装 UPX*、追加 .jd 诱饵节（UPX banner/JPEG/PDB 路径）
```

每次换 `--seed` 得到完全不同的 opcode 编号/别名、handler 机器码形态、密钥与诱饵
常量、**加密公式族**（kmix 常数/通道组合/合并式）、KSET 重密钥方案、诱饵叙事主题与
字符串组合——同一份源码的两个构建之间没有可复用的静态特征。

## 保护机制速览（详见 DESIGN.md §1-2）

| 层 | 机制 |
|---|---|
| codegen | 业务函数 → 栈式 VM 字节码；真字符串/真常量只以密文出现在字节码流中 |
| 字节码加密 | `plain[p] = cipher[p] ^ ks8(p)`，ks8 位置相关，由 K1/K2/K3 派生；**公式族每构建随机**；操作数再按位置二次混叠 |
| 反脚本 (KSET) | 每函数入口 1-3 层 prologue 用真实 VM 算术算出 delta 并 KSET 重密钥——自写解密脚本必须先解析变长指令流、求值 prologue、复现逐构建重密钥方案，才能解过第一个 KSET；另有永不执行的垃圾块污染模式匹配 |
| 密钥拼装 | K1/K2/K3 与分发表掩码在运行时由诱饵函数返回值 + 常量算术拼出（无一处明文） |
| xref 断裂 | 分发/host/VM 函数表全部 XOR 掩码，静态 call 目标不可解析 |
| 多态 handler | 同一语义 op 每次构建生成不同机器码模板；~50 语义 op × 1-3 别名 ≈ 200+ 匿名小函数 |
| 反调试 | IsDebuggerPresent 参与密钥异或：挂调试器 → 密钥变 → 字节码变垃圾，静默跑偏 |
| PE 伪装 (pepolish) | 每构建从 18 主题诱饵库抽一条叙事（UPX/ASPack/VMProtect/NSIS/libpng/sqlite/zlib/游戏/驱动…或两主题混搭）：节名、导出名、PDB 路径、banner、~130 条模板化字符串 |

## 已知限制（诚实声明）

- 威胁模型是 **静态 LLM 分析**（含其自写解密/求值脚本——这部分已被 KSET 分层
  重密钥与逐构建公式族针对性设防）。动态调试（attach 后需先 patch 密钥）、Unicorn
  模拟、符号执行、人工专家 + IDAPython 全量 handler 分类仍可恢复——本工具抬高
  的是成本与出错率，不是信息论意义上的不可恢复。
- subset-C 限制：无浮点/struct/多维数组/递归；被保护函数只能通过注册的 host
  函数与外界交互。
- MSVC `cl` 依赖（代码生成端是 C 源码级方案，尚未做直接吃 PE 的模式）。
- 本机第三方 AV 可能拦截新鲜构建的混淆 exe：换 seed 重试即可（run_demo /
  run_selftest 已内置重试与随机目录）。

## 许可证

MIT，见 [LICENSE](LICENSE)。`evidence/` 内的 exe 为实验样本（含诱饵字符串与
假节名），仅供静态分析复现。
