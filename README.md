# LLMVM — 针对 AI 逆向工程的代码虚拟化保护器

**[English](README.en.md) | 简体中文**

## 概述

传统壳与 VM 保护器的威胁模型是人工逆向分析。LLMVM 将对抗目标转向 **基于 LLM 的自动化静态逆向工程**——以 IDA / Hex-Rays 为分析前端的大模型代理。

LLMVM 不追求信息论意义上的不可恢复，而是针对 LLM 静态分析的实际工作方式构建系统性的干扰与成本壁垒：

- **结论诱导**：每次构建注入约 130 条主题连贯的诱饵字符串与整套伪装元数据，将分析引向错误的程序身份与功能叙事；
- **信息隐藏**：真实代码以逐构建随机化的加密字节码形式存在，密钥仅在运行时由诱饵函数拼装，静态手段无法读取真实语义；
- **成本壁垒**：多态 handler、别名 opcode、死代码与诱饵函数共同膨胀分析所需的上下文与计算量。

完整设计（LLM 的 11 种失败模式与对抗机制的映射表）见 [DESIGN.md](DESIGN.md)。

## 工作原理

```
vm_targets.c（subset-C 源码）
        │  vmc.py
        ▼
protected.c（VM 解释器 + wrapper + 诱饵函数）
        │  MSVC cl
        ▼
       exe ──pepolish──▶ final.exe

同一逻辑的原生 C ──MSVC cl──▶ plain.exe（对照组）
```

LLMVM 将目标函数编译为自定义栈式虚拟机的加密字节码：字节码在文件中全部为密文，密钥仅在运行时由若干诱饵函数的返回值拼装得出；解释器由 200 余个每次构建形态各异的多态 handler 构成，所有函数表均经 XOR 掩码处理。

正确性判据：构建同时产出未保护的原生版本（`plain.exe`）作为对照组，两版程序的标准输出必须逐字节一致。`run_demo.py` 与 `run_selftest.py` 自动执行该比对，任何不一致即判定构建失败。

## 环境要求

- Windows x64 + VS2017（MSVC 14.16）。默认路径为 `D:\VS17`，如安装在其他位置，
  请设置环境变量 `LLMVM_VCVARS` 指向你的 `vcvars64.bat`。
- Python 3.10+（纯标准库，无第三方依赖）。
- （可选）IDA Pro 9.1 + idalib，用于复现验证报告：

  ```bash
  pip install "C:\Program Files\IDA Professional 9.1\idalib\python"
  python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"
  ```

## 快速开始

```bash
# 1. 演示：构建原生对照组与 VM 保护版（含 pepolish 与假导出），运行并自动比对输出
python run_demo.py

# 2. 语义等价回归：随机种子批量构建 VM / 原生两版，输出必须逐字节一致
python run_selftest.py

# 3. handler 模板恒等式测试（30 个多态模板 × 大量随机输入，0 失配为通过）
python tools_tpl_test.py

# 4. 对任意 exe 生成 IDA 分析报告（复现 REPORT.md 中的验证实验）
python tools_ida.py evidence/sample_alpha.exe my_report.txt 14

# 5. 折叠地面真值密钥并校验构建确定性（seed 见 evidence/seed.txt）
python evidence/fold_true_key.py

# 6. v3 内层程序差分审计：真实构建的每个内层程序 vs 原生语义（0 失配为通过）
python evidence/inner_audit.py <seed>
```

## 保护自己的代码

1. 将待保护函数编写为 subset-C 源文件。支持：int8..int64 / uint8..uint64、指针、
   一维数组、if/else、for/while、break/continue、算术/位/比较运算、函数互调。
   不支持：struct、浮点、多维数组、递归、变参。库函数不可直接调用，host 函数
   （如 puts/printf）须在 `host_config.py` 中显式注册。
   参考示例：`demo/vm_targets.c`、`tests/selftest_targets.c`。
2. 入口 `main` 独立成文件（`--main`）。生成器会将其对保护函数的调用替换为
   VM wrapper。
3. 生成、编译与伪装：

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # vmlib/build.py 的 build_exe() 封装了此步骤
python pepolish.py final.exe      # 节名伪装为 UPX*，追加含诱饵内容的 .jd 节
```

更换 `--seed` 后，opcode 编号与别名、handler 机器码形态、密钥与诱饵常量、
加密公式族、KSET 重密钥方案、诱饵叙事主题与字符串组合全部重新生成——同一
源码的任意两次构建之间不存在可复用的静态特征。

## 保护机制概览

完整细节见 [DESIGN.md](DESIGN.md) §1–2。"每次构建"指更换 `--seed` 后，右列
全部内容重新生成。

| 针对的 LLM 分析行为 | 对抗机制 |
|---|---|
| 以字符串锚定关键代码（依赖度最高的分析路径） | 真实字符串与常量仅以密文形式存在于字节码流中，静态不可见 |
| 依据节名 / 导出名 / PDB 路径推断程序身份 | 每次构建从 18 套主题库（UPX、VMProtect、NSIS、sqlite、libpng、游戏、驱动等，支持双主题混搭）抽取伪装身份：节名、导出名、PDB 路径及约 130 条主题连贯的诱饵字符串 |
| 常量指纹识别（MD5 初始化值、CRC32 多项式等） | 诱饵中刻意植入标准指纹常量，将归纳分析引向伪装叙事 |
| 基于反编译伪代码的语义归纳 | 同一语义操作每次构建生成不同机器码模板，200 余个匿名 handler 使伪代码失去可读性 |
| 沿 call / xref 遍历调用图 | 分发表、host 表与 VM 函数表全部经 XOR 掩码，静态 call 目标不可解析 |
| 上下文预算约束 | handler 数量、别名 opcode、死代码与诱饵函数（数量不少于真实函数）共同膨胀分析成本 |
| 自写解密 / 求值脚本 | 加密公式族逐构建随机；每函数入口的 KSET 分层重密钥要求脚本先解析变长指令流并求值 prologue 算术，方能通过第一层；永不执行的垃圾块进一步污染模式匹配 |
| 语义 lift 与自建模拟器（v2 盲测实证的最强攻击） | v3 VM-in-VM：承重 handler 本身即为另一层加密字节码程序，两级 lift 之间不存在可验证的中间产物 |
| 调试器附加 | IsDebuggerPresent 参与密钥异或：附加调试器即改变密钥，字节码解密为无效数据，程序静默执行错误逻辑 |

## 验证方法

有效性验证采用四层协议（完整记录见 [REPORT.md](REPORT.md)）：

1. **行为等价回归**：跨随机种子批量构建 VM 版与原生版，输出必须逐字节一致
   （`run_selftest.py`）。
2. **作者侧恢复实验**：使用 idalib（IDA 9.1 无界面分析库）对保护产物进行真实
   恢复尝试，评估产物实际泄露的信息量。
3. **不知情盲测**：由同模型、不掌握本项目设计信息的子代理分别分析保护组与
   对照组样本，按五项标准评分（入口定位、字符串恢复、算法恢复、诱饵误判、
   综合判定）。对照组被完全恢复（验证盲测方法有效），保护组均被诱饵误导。
4. v2 / v3 轮盲测**明确允许并鼓励**代理自写解密与模拟脚本开展纯静态攻击，
   直接检验反脚本机制的有效性。

各轮盲测样本、地面真值密钥与复核脚本存档于 [evidence/](evidence/)。v3
（VM-in-VM、反规范化、公式变体、元数据清理）针对 v2 盲测中发现的最强攻击
路径设计，机制见 [DESIGN.md](DESIGN.md) §2b，复测见 [REPORT.md](REPORT.md) §6。

## 已知限制

- 威胁模型限定为**静态 LLM 分析**。动态调试（附加后修补密钥）、Unicorn 模拟、
  符号执行、人工专家借助 IDAPython 完成全量 handler 分类仍可恢复语义——LLMVM
  抬高的是攻击成本与出错率，不构成信息论意义上的不可恢复。
- 语言限制：subset-C 不支持浮点、struct、多维数组与递归；被保护函数仅能通过
  注册的 host 函数与外界交互。
- 构建依赖 MSVC `cl`：代码生成端为 C 源码级方案，暂不支持直接处理 PE。
- 部分第三方杀软可能拦截新生成的混淆 exe：更换 seed 重试即可（run_demo /
  run_selftest 已内置重试与随机目录机制）。

## 许可证

MIT，见 [LICENSE](LICENSE)。`evidence/` 目录下的 exe 为实验样本（含诱饵字符串
与伪装节名），仅供静态分析复现，请勿执行。
