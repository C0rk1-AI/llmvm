# LLMVM — 针对 AI 逆向工程的代码虚拟化保护器

**[English](README.en.md) | 简体中文**

## 概述

传统壳和 VM 保护器的对手是人。LLMVM 针对的是另一类攻击者：以 IDA / Ghidra
为分析前端、自动执行静态逆向的 LLM 代理。这类代理读反编译伪代码很快，习惯
靠字符串和常量定位关键代码、沿交叉引用梳理调用关系；但它们在有限的上下文
窗口里工作，也容易被看似合理的结论带偏。

LLMVM 从三个方面利用这些特点：

- 真实代码只以加密字节码存在，密钥要到运行时才由若干诱饵函数的返回值拼出，
  静态手段读不到；
- 每次构建注入约 130 条主题连贯的诱饵字符串，以及整套伪装元数据（节名、
  导出名、PDB 路径），诱导分析得出错误的程序身份；
- 200 余个多态 handler、别名 opcode、死代码和诱饵函数共同抬高分析所需的
  上下文与计算量。

LLMVM 不宣称被保护代码不可恢复，它提高的是攻击成本和出错率。完整设计
（LLM 的 11 种失败模式与对抗机制的对应关系）见 [DESIGN.md](DESIGN.md)。

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

目标函数被编译为自定义栈式虚拟机的加密字节码：文件里只有密文，密钥在运行时
由诱饵函数拼装。解释器由 200 余个 handler 组成，同一语义操作在每次构建中
生成不同的机器码；所有函数表均经 XOR 掩码。

每次构建同时产出未保护的原生版本（`plain.exe`）作为对照组，两版程序的标准
输出必须逐字节一致，否则构建判为失败。`run_demo.py` 与 `run_selftest.py`
自动执行该比对。

## 环境要求

- Windows x64 + MSVC（VS2017 / 2019 / 2022 或独立的 Build Tools，需含 C++
  桌面开发工作负载）。工具链自动定位的顺序：环境变量 `LLVMVM_VCVARS` →
  PATH 里可用的 `cl`（VS 开发者命令行）→ vswhere → 常见安装路径。都找不到
  时报错并提示设置 `LLVMVM_VCVARS`。
- Python 3.10+，纯标准库，无第三方依赖。
- 可选：IDA Pro 9.1 + idalib，用于复现验证报告：

  ```bash
  pip install "C:\Program Files\IDA Professional 9.1\idalib\python"
  python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"
  ```

## 快速开始

```bash
# 演示：构建原生对照组与 VM 保护版（含 pepolish 与假导出），运行并自动比对输出
python run_demo.py

# 语义等价回归：跨随机种子批量构建 VM / 原生两版，输出必须逐字节一致
python run_selftest.py

# handler 模板恒等式测试（35 个多态模板 × 大量随机输入，0 失配为通过）
python tools_tpl_test.py

# 对任意 exe 生成 IDA 分析报告（复现 REPORT.md 中的验证实验）
python tools_ida.py evidence/sample_alpha.exe my_report.txt 14

# 折叠地面真值密钥并校验构建确定性（seed 见 evidence/seed.txt）
python evidence/fold_true_key.py

# v3 内层程序差分审计：每个内层程序 vs 原生语义，0 失配为通过
python evidence/inner_audit.py <seed>
```

## 保护自己的代码

1. 把待保护函数写在一个 subset-C 源文件里，语言支持：

   - 类型：int8..int64 / uint8..uint64、`float` / `double`、指针；
   - 数据结构：一维与多维数组（全局、局部均可），struct（可嵌套、可作数组
     成员，`.` / `->` 成员访问）；
   - 控制流：if / else、for / while、break / continue；
   - 运算：算术 / 位 / 比较，int 与 float 混用时按 C 规则做隐式转换；
   - 函数：互调、递归（直接递归，或经前置声明的相互递归）、变参。

   库函数不能直接调用。需要 puts、printf 这类宿主函数时，先在
   `host_config.py` 里注册；浮点参数或返回值用 `'sig'` 字段标注 ABI，例如
   `'sqrt': {'arity': 1, 'sig': 'd', 'ret': 'd'}`。

   几条约定：

   - struct 按 MSVC 默认对齐布局。跨函数边界只能传指针：按值传参、按值
     返回、整体赋值都不支持。
   - 局部数组和局部 struct 存放在每次调用独立的帧存储中，上限 512 字节，
     递归安全。
   - 变参函数声明为 `uint64_t vsum(uint64_t nv, ...)`：固定形参至多 3 个，
     最后一个必须叫 `nv`，值为变参个数（单次调用至多 32 个）。函数体开头
     调用 `vv_start();`，之后每次 `vv_next()` 按顺序取一个变参，返回的是
     u64 位槽：float 变参在调用点已提升为 double 位模式，窄整数已做符号
     扩展。调用点请使用 64 位字面量（如 `10ull`）。原生对照组按
     `va_arg(ap, uint64_t)` 读取变参，32 位字面量在 MSVC 变参 ABI 下高位
     未定义。

   写法参考 `demo/vm_targets.c`、`tests/selftest_targets.c`。

2. 入口 `main` 单独放一个文件（`--main`），生成器会把它对保护函数的调用
   改写为 VM wrapper。
3. 生成、编译、伪装：

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # vmlib/build.py 的 build_exe() 封装了这一步
python pepolish.py final.exe      # 节名伪装为 UPX*，追加含诱饵内容的 .jd 节
```

换一个 `--seed`，opcode 编号与别名、handler 机器码形态、密钥与诱饵常量、
加密公式、KSET 重密钥方案、诱饵主题与字符串组合全部重新生成。同一份源码
构建两次，产物之间没有可复用的静态特征。

## 保护机制

下表按针对的分析行为归纳机制，细节见 [DESIGN.md](DESIGN.md) §1–2。表中
"每次构建"指更换 `--seed` 后右列内容重新生成。

| 针对的分析行为 | 机制 |
|---|---|
| 靠字符串锚定关键代码（使用最多的分析路径） | 真实字符串与常量只在字节码流中以密文存在，静态不可见 |
| 靠节名 / 导出名 / PDB 路径判断程序身份 | 每次构建从 18 套主题（UPX、VMProtect、NSIS、sqlite、libpng、游戏、驱动等，支持两套混搭）抽取伪装身份，含约 130 条主题连贯的诱饵字符串 |
| 靠常量指纹认算法（MD5 初值、CRC32 多项式等） | 诱饵中刻意埋入标准指纹常量，把归纳分析引向伪装叙事 |
| 读反编译伪代码归纳语义 | 同一语义操作每次构建生成不同机器码模板，200 余个匿名 handler 使伪代码失去可读性 |
| 沿 call / xref 遍历调用图 | 分发表、host 表与 VM 函数表全部 XOR 掩码，静态解析不出 call 目标 |
| 上下文窗口有限 | handler 数量、别名 opcode、死代码与诱饵函数（数量不少于真实函数）共同膨胀分析量 |
| 自写解密 / 求值脚本 | 加密公式逐构建随机；每个函数入口有 KSET 分层重密钥，脚本须先解析变长指令流、求出 prologue 算术才能通过第一层；永不执行的垃圾块污染模式匹配 |
| 语义 lift 加自建模拟器（v2 盲测中的最强攻击） | v3 VM-in-VM：承重 handler 本身又是一层加密字节码程序，两次 lift 之间没有可验证的中间产物 |
| 附加调试器 | IsDebuggerPresent 参与密钥异或：附加即改变密钥，字节码解密为无效数据，程序静默执行错误逻辑 |

## 验证方法

验证分四部分，完整记录见 [REPORT.md](REPORT.md)：

1. 行为等价回归：跨随机种子批量构建 VM 版与原生版，输出必须逐字节一致
   （`run_selftest.py`）。
2. 作者侧恢复实验：用 idalib（IDA 9.1 的无界面分析库）对保护产物做真实
   恢复尝试，评估产物实际泄露的信息量。
3. 不知情盲测：由同模型、不了解本项目设计的子代理分别分析保护组与对照组，
   按入口定位、字符串恢复、算法恢复、诱饵误判、综合判定五项评分。对照组
   被完整恢复（说明盲测方法有效），保护组全部被诱饵带偏。
4. 反脚本攻击：v2 / v3 两轮盲测明确允许并鼓励代理自写解密、模拟脚本开展
   纯静态攻击，直接检验反脚本机制。

上述实验和盲测的分析环境与被防御的攻击形态一致：Claude Code 驱动 GLM-5.3
模型，经 idalib MCP 工具接入 IDA 做静态分析。

各轮盲测样本、地面真值密钥与复核脚本存档于 [evidence/](evidence/)。v3
（VM-in-VM、反规范化、公式变体、元数据清理）针对 v2 盲测中发现的最强攻击
路径设计，机制见 [DESIGN.md](DESIGN.md) §2b，复测见 [REPORT.md](REPORT.md) §6。

## 已知限制

- 威胁模型只覆盖静态 LLM 分析。动态调试（附加后修补密钥）、Unicorn 模拟、
  符号执行、人工借 IDAPython 完成 handler 全量分类仍可恢复语义——LLMVM
  抬高的是成本与出错率，不承诺不可恢复。
- 语言层面：struct 只能按指针跨函数传递，不支持按值传参 / 返回与整体赋值；
  没有 switch 和函数指针；与外界的交互只能走注册过的 host 函数。
- 构建依赖 MSVC `cl`，代码生成端输出 C 源码，暂不支持直接输入 PE。
- 个别杀软可能拦截新生成的混淆 exe，换个 seed 重试即可（run_demo /
  run_selftest 已内置重试与随机目录机制）。

## 许可证

MIT，见 [LICENSE](LICENSE)。`evidence/` 目录下的 exe 是实验样本（含诱饵
字符串与伪装节名），仅供静态分析复现，请勿执行。
