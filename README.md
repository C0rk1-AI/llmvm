# LLMVM — 面向 LLM 静态分析的代码虚拟化保护器

**[English](README.en.md) | 简体中文**

## 这是什么

大多数壳 / VM 保护器的对手是"人"——坐在 IDA 前面的逆向工程师。LLMVM 的对手不一样：**正在用 IDA / Hex-Rays 静态分析你程序的 LLM**（比如各种基于大模型的自动化逆向 / 审计代理）。

它的目标不是让程序"永远无法被还原"，而是让 LLM 在分析被保护程序时：

- 被 130+ 条以假乱真的诱饵字符串和一整套假身份带偏，得出错误结论；
- 或者在上下文预算 / 成本耗尽之前，根本读不到真实代码。

打个比方：保护前，LLM 看到的是一页清晰的反编译伪代码；保护后，是一本每一页都用不同密码锁住、还夹了几十页假情报的厚书——而且每印一本，密码和假情报全部换新。

完整设计思路（LLM 的 11 种失败模式 → 对抗机制映射表）见 [DESIGN.md](DESIGN.md)。

## 工作原理

```
vm_targets.c（subset-C 源码）
        │  vmc.py 编译
        ▼
protected.c（VM 解释器 + wrapper + 诱饵函数）
        │  MSVC cl
        ▼
       exe ──pepolish 伪装──▶ final.exe

同样逻辑的原生 C ──MSVC cl──▶ plain.exe（对照组）
```

核心思路一句话：**把要保护的函数编译成一台自定义栈式 VM 的加密字节码**。字节码在文件里全是密文，密钥要等程序跑起来、由几个"看似垃圾"的诱饵函数现场拼出来；解释器本体是 200+ 个每次构建长得都不一样的匿名小函数，所有函数表再用 XOR 掩码搅乱。

那怎么确认保护过程没有改坏程序？构建时同时产出一份**不加保护的原生版**（`plain.exe`）作为对照组，两版程序的标准输出必须**逐字节一致**——`run_demo.py` / `run_selftest.py` 会自动 diff，任何不一致直接判失败。

## 环境要求

- Windows x64 + VS2017（MSVC 14.16）。默认使用 `D:\VS17`，装在别处请设环境变量
  `LLMVM_VCVARS` 指向你的 `vcvars64.bat`。
- Python 3.10+（纯标准库，无第三方依赖）。
- （可选）IDA Pro 9.1 + idalib，用于复现验证报告：

  ```bash
  pip install "C:\Program Files\IDA Professional 9.1\idalib\python"
  python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"
  ```

## 快速开始

```bash
# 1. 演示：构建原生对照组 + VM 保护版（含 pepolish + 假导出），运行并自动 diff
python run_demo.py

# 2. 语义等价回归：随机种子批量构建 VM / 原生两版，输出必须逐字节一致
python run_selftest.py

# 3. handler 模板恒等式测试（30 个多态模板 × 大量随机输入，0 失配为过）
python tools_tpl_test.py

# 4. 对任意 exe 生成 IDA 分析报告（复现 REPORT.md 中的验证实验）
python tools_ida.py evidence/sample_alpha.exe my_report.txt 14

# 5. 折叠地面真值密钥，并校验构建确定性（seed 见 evidence/seed.txt）
python evidence/fold_true_key.py

# 6. v3 内层程序差分审计：真实构建的每个内层程序 vs 原生语义（0 失配为过）
python evidence/inner_audit.py <seed>
```

## 保护你自己的代码

**第 1 步：把要保护的函数写成 subset-C。**

支持：int8..int64 / uint8..uint64、指针、一维数组、if/else、for/while、
break/continue、算术/位/比较运算、函数互调。
不支持：struct、浮点、多维数组、递归、变参。库函数不能直接调用——host 函数
（如 puts/printf）需在 `host_config.py` 中显式注册。

现成例子可参考 `demo/vm_targets.c` 和 `tests/selftest_targets.c`。

**第 2 步：入口 main 写在单独文件里**（`--main`）。生成器会把其中对保护函数的
调用替换成 VM wrapper。

**第 3 步：生成 + 编译 + 伪装：**

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # vmlib/build.py 的 build_exe() 封装了这一步
python pepolish.py final.exe      # 节名伪装成 UPX*、追加含诱饵的 .jd 节
```

**关于 seed**：每次换 `--seed`，会得到完全不同的 opcode 编号与别名、handler
机器码形态、密钥与诱饵常量、加密公式族、KSET 重密钥方案、诱饵叙事主题与
字符串组合——同一份源码的两个构建之间，没有任何可复用的静态特征。

## 保护机制速览

完整细节见 [DESIGN.md](DESIGN.md) §1–2。"每次构建"意味着换一个 `--seed`，
下表右侧的所有东西都会重新生成。

| 针对的 LLM 行为 | 对策 |
|---|---|
| 拿字符串定位关键代码（最重依赖） | 真字符串/真常量只以密文出现在字节码流中，静态完全不可见 |
| 靠节名/导出名/PDB 路径猜程序身份 | 每次构建从 18 套主题（UPX、VMProtect、NSIS、sqlite、libpng、游戏、驱动……或两主题混搭）抽一套假身份：假节名、假导出、假 PDB 路径、约 130 条连贯的假字符串 |
| 常量指纹（MD5 初值、CRC32 多项式等） | 诱饵里专门植入这些"标准指纹"，把归纳引向假叙事 |
| 读伪代码做语义归纳 | 同一语义操作每次构建生成不同机器码模板，200+ 个匿名小函数，伪代码基本不可读 |
| 顺 call / xref 摸调用图 | 分发表 / host 表 / VM 函数表全部 XOR 掩码，静态 call 目标不可解析 |
| 上下文预算耗尽 | handler 数量 + 别名 opcode + 死代码 + 诱饵函数（数量 ≥ 真函数）一起膨胀分析成本 |
| 自写 Python 解密/求值脚本 | 加密公式族每次构建随机；每函数入口 KSET 分层重密钥——脚本必须先解析变长指令流、求值 prologue 算术才能解过第一层；另有永不执行的垃圾块污染模式匹配 |
| 语义 lift + 自建模拟器（v2 盲测实证的最强攻击） | v3 VM-in-VM：承重 handler 本身又是另一层加密字节码程序，两级 lift 之间没有任何可验证的中间产物 |
| 动态调试 | IsDebuggerPresent 参与密钥异或：挂着调试器密钥就变，字节码解出来是垃圾，程序静默跑偏 |

## 怎么知道它有效

不是拍脑袋，验证协议（详见 [REPORT.md](REPORT.md)）：

1. **行为等价**：多种子批量构建，VM 版与原生版输出必须逐字节一致（`run_selftest.py`）。
2. **本人复现攻击**：用 idalib（IDA 9.1 的无界面分析库）对保护后的 exe 做真实
   恢复尝试，评估产物信息量是否足以还原。
3. **不知情盲测**：让同模型、但完全不知道本项目设计的子代理，分别分析保护组与
   对照组 exe，产出报告并按 5 项标准评分（入口是否找对、字符串是否恢复、算法
   是否恢复、是否被诱饵带偏、总判定）。对照组被完全恢复（证明盲测方法有效），
   保护组全部被带偏。
4. v2 / v3 盲测明确**允许并鼓励**代理自写解密 / 模拟脚本的纯静态攻击——直接
   检验"反脚本"这道墙。

各轮盲测样本、地面真值密钥与复核脚本存档于 [evidence/](evidence/)，可直接复跑。
v3（VM-in-VM + 反规范化 + 公式变体 + 元数据清理）针对 v2 盲测中发现的最强攻击
路径，机制见 [DESIGN.md](DESIGN.md) §2b，复测见 [REPORT.md](REPORT.md) §6。

## 已知限制（诚实声明）

- **威胁模型是静态 LLM 分析**。动态调试（attach 后先 patch 密钥）、Unicorn 模拟、
  符号执行、人工专家用 IDAPython 全量分类 handler，仍然可以恢复——本工具抬高的
  是成本与出错率，不是信息论意义上的不可恢复。
- **语言是 subset-C**：不支持浮点 / struct / 多维数组 / 递归；被保护函数只能通过
  注册的 host 函数与外界交互。
- **依赖 MSVC `cl`**：代码生成端是 C 源码级方案，尚未做直接吃 PE 的模式。
- **本机第三方 AV 可能拦截新鲜构建的混淆 exe**：换 seed 重试即可（run_demo /
  run_selftest 已内置重试与随机目录）。

## 许可证

MIT，见 [LICENSE](LICENSE)。`evidence/` 内的 exe 为实验样本（含诱饵字符串与
假节名），仅供静态分析复现，勿执行。
