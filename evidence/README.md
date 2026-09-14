# evidence/ — 验证实验的样本、地面真值与复核脚本

本目录存档 REPORT.md 各轮验证的可复核材料。文件按所属构建分组；
所有脚本均为相对路径，在仓库根目录结构不变的前提下直接可跑（纯标准库；
`my_check.py` 另需 idalib）。

## v1 盲测构建（seed 881831599，REPORT §1-§4）

| 文件 | 说明 |
|---|---|
| `sample_alpha.exe` | 保护组盲测样本（alpha/beta 分析的同一份；pepolish + 假导出） |
| `sample_gamma.exe` | 原生对照组（= `demo_plain.exe`，逐字节同） |
| `blind_alpha_report.md` / `blind_beta_report.md` | 不知情代理对保护组的完整交付 |
| `blind_gamma_report.md` | 不知情代理对对照组的完整交付（完全恢复，对照成立） |
| `ida_report_vm.txt` / `ida_report_plain.txt` | `tools_ida.py` 生成的两份 idalib 全量报告（§2 本人分析基础） |
| `my_check.py` | §2.2 的 idalib 核查脚本（handler 计数/匿名率/blob 定位；需 idalib，目标为 `sample_alpha.exe`）。注：新鲜自动分析识别出的函数数会少于 REPORT 引用的会话累积计数（139 vs 264），属 IDA 分析轮次差异，地址级锚点（假导出/四 blob VA/16640 字节区域）完全一致 |
| `verify_key.py` | §4.2 的"文件镜像 XOR 检验"脚本——**按设计必然失败**（掩码表运行时才写入，文件镜像为无关数据），保留作叙事记录；目标为 `sample_alpha.exe` |

## v2 盲测构建（seed 534145564，REPORT §5）

| 文件 | 说明 |
|---|---|
| `sample_delta.exe` | v2 保护组盲测样本（delta/epsilon 分析的同一份） |
| `gt_fold.txt` | v2 构建密钥地面真值（`fold_true_key.py` 以当期 seed.txt 跑出的输出存档） |
| `gt_listing_534145564.txt` | v2 构建四函数明文字节码清单（含 KSET 层位置/delta） |

## v3 复核构建（seed 583975156，REPORT §6；当前 `seed.txt` 指向它）

| 文件 | 说明 |
|---|---|
| `sample_zeta.exe` | v3 保护组盲测样本（zeta/eta 分析的同一份；VM-in-VM + 反规范化） |
| `seed.txt` / `legend.txt` / `theme.json` | v3 构建 seed、构建期 legend（opcode 映射/毒槽数）、诱饵主题 |
| `protected.c` | v3 构建生成的解释器源码（`fold_true_key.py` 重放比对对象） |
| `gt_listing_583975156.txt` | v3 构建明文字节码清单 |
| `gt_inner_583975156.txt` | v3 内层密钥真值（I1/I2/I3/IMK + 内层 scheme） |
| `fold_true_key.py` | 重放构建折叠真值密钥；对当前 `seed.txt` 输出并校验 `protected.c` 逐字节一致 |
| `gt_inner_keys.py` | 捕获真实 InnerBuild 打印内层密钥/scheme/innerized 别名 |
| `gt_listing.py` | 当前 seed 的明文字节码地面真值清单（注意 docstring：linearize 只能调一次） |
| `inner_audit.py` | v3 内层程序差分审计（真实构建 InnerBuild 的 python 镜像 vs 原生语义，`python evidence/inner_audit.py <seed>`） |
| `inner_dis.py` | 反汇编某个外层别名对应的内层程序（`python evidence/inner_dis.py <seed> PUSHI`） |
| `inner_check.py` | 内层 ISA 的差分 fuzz（300 个随机构建全量跑，`vmlib/inner.py` 文档所指；纯 Python 无需 MSVC） |

## 关于可复现性

- 代码生成端逐构建确定：同 seed 重放 `protected.c` / `theme.json` / `legend`
  逐字节一致（`fold_true_key.py` 即此校验，REPORT §4.2）。
- exe 层不承诺逐字节一致：MSVC 链接器在 PE 头写入链接时间戳，且本机 AV
  对新链 exe 的拦截会触发重试改名；对照以上样本请以 `protected.c` 与
  密钥/清单类地面真值为准。
- 本目录所有 exe 均为实验样本（含诱饵字符串与假节名，行为见 REPORT §1），
  仅供静态分析复现，勿执行。
