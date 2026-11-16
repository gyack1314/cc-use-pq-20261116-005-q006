# 气候指标批次采集台账

本项目供研究团队离线接收不同机构交付的气候指标摘录。系统核验来源和指标契约，保留每次批次修订，记录质量证据，并发布不可变、可校验的快照。演示数据均为本地合成数据，不代表真实气候观测，也不在运行时访问外部网站。

使用 Python 3.11 或更新版本即可运行，无第三方依赖。以下命令均从项目根目录执行。

## 快速演示

运行 python -m climateledger demo --workspace fixtures，完成本地演示：创建 SQLite 数据库、注册合成指标与来源、摄入两行数据、发布快照并校验导出。再次执行会重用相同批次和发布版本。

单独使用时，把 --db path/to/ledger.sqlite3 放在子命令前。依次执行 register-indicator contract.json、register-source contract.json；需要单位换算时执行 register-unit rule.json。用 ingest batch.manifest.json 摄入数据，batch ID 查看记录；待审批次用 approve ID REVISION 审核，然后用 publish ID REVISION 发布。

export VERSION --output bundle.json 导出指定快照，verify bundle.json 检查摘要，series INDICATOR --version VERSION 查询发布值。coverage、discrepancies、compare、replay 和 audit 分别用于查看覆盖、来源分歧、版本变化、原始文件重放及审计链。

## 来源授权生命周期

资料提供方可在批次发布后撤回对外公开许可。授权以**不可变决策流**记录，来源契约本身不变：用 record-license decision.json 录入决策，包含 source、action（revoke 撤销或 grant 重新授权）、effective_at（带时区的生效时间）、notification_id（通知编号，幂等键）、reason，以及可选作用域 indicator 和 period（period 必须配合 indicator，且与指标周期格式一致）。revoke 必须带 mode：mask 表示导出时遮蔽观测值但保留出处，stop 表示该观测不得进入审核与发布。

作用域按特异性匹配：精确到（指标、期间）的决策优先于指标级，指标级优先于来源级。状态完全由截至某时刻的决策流计算，因此生效时间决定结论，与录入先后无关；相同 notification_id 的撤权通知重放只返回原决策，不产生新事件或新状态。

- **采集识别**：摄入时把当时的许可快照写入批次 metadata.license_snapshot。撤权不阻断内部留痕，批次与测量仍完整保存，数据从何而来始终可查；摄入返回值同时标出命中 stop 的测量。
- **发布前逐条检查**：publish（和 preview）对每条可导出出处执行许可检查。命中 stop 直接以 license_withheld 拒绝发布，approve 同样拦截；命中 mask 则把 value 置空、unit 标为 restricted，并在 manifest.license_restrictions 与 release_restrictions 表中记录每条限制的作用域、原因、通知编号和决策 ID。
- **历史快照不可变**：已发布版本的 manifest、digest、entries 永不重写，旧快照始终逐字节可验证。重新授权只影响之后的新发布：新版本会从底层测量恢复已解限出处的真实值，而旧版本保留自己当时记录的遮蔽，旧决策不被倒改。
- **按当前许可再导出**：export-licensed VERSION 在不修改基础快照的前提下附加 license_overlay，列出当前许可要求新增的 masked 与 withheld（stop）范围；verify 可同时校验普通包与覆盖层包。
- **审计**：audit 的 license_audit 段统计决策数、限制数，检测重复通知和引用不到决策的悬空限制；release 审计把合法遮蔽（masked_count）与数据损坏（measurement_mismatch、unrecorded_mask、restriction_table_mismatch）区分开。

license-decisions（可按 --source 过滤）查看决策流，license-state SOURCE [--at ISO时间] 查看某时刻的有效许可，restrictions VERSION 查看某版本发布时固化的限制。

## 输入与状态

指标契约包含 key、title、canonical_unit 和 cadence（月份或年份）；可附带上下限、精度和负值许可。来源契约包含标识、标题、授权说明及允许提交的指标列表。相同标识下契约不可静默改写。单位规则采用“原值乘以 factor 加 offset”换算为规范单位。

批次清单指定来源、外部批次编号、同目录的 CSV 或 JSON 数据文件、文件 SHA-256、行数及四个字段的列映射：indicator、period、value、unit。文件仅从本地读取。非法行形成拒收证据；序列内部缺期和已发布值的变更需人工审核，不会被悄悄修正。相同字节重复提交幂等，内容变化形成修订。清单中的行数和摘要可检测不完整或被修改的输入。

发布版本包含上个版本的摘要、来源文件摘要、批次修订、当前测量集合及导出摘要。不同来源对同一指标和期间的观测保持独立。旧版本始终可以独立导出和验证。被许可遮蔽的条目 value 为空、unit 为 restricted，其真实值仍保留在内部测量表中，待重新授权后可在新版本恢复导出。

## 验证命令

python -m unittest discover -s tests -v

python -m compileall -q climateledger

python -m climateledger demo --workspace fixtures
