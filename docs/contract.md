# Offline authorization audit v1

为数据目录管理员审计一份合成RBAC快照。roles(id,inherits)为有向无环继承图，子角色获得父角色权限；
users(id,roles)是直接赋权，grants(id,role,action,resource,effect)为授权规则。未知引用、重复ID、继承环拒绝。
roles<=500、users<=2000、grants<=5000、requests<=10000；文本标识<=128字符无首尾空白/控制字符。
资源为大小写敏感逻辑路径，非宿主文件路径；只允许精确路径、全局*或末端/*前缀。
/docs/*匹配/docs/a及/docs/a/b，不匹配/docs或/docs2/a；拒绝//、.、..、结尾/及中间*。
动作只支持精确字符串或完整*。请求必须具体，不允许*。

请求汇总用户全部有效角色的匹配规则；任意deny优先于allow，没有匹配则default_deny。
输出所有匹配grant ID、来源role和effect，不隐藏被deny压过的allow。
exclusions每项两个不同的角色，若用户有效角色同时含这两个则给出职责分离冲突。
冲突是审计告警，不隐式撤销授权，也不改变请求的deny-overrides决策。
角色拥有但无grant不是allow；空角色用户合法，所有请求默认拒绝。

样例Ada继承reader，Q1 allow，Q2 explicit_deny，Bo的Q3 default_deny；
Q4针对/docs本身也default_deny。Ada的finance/auditor出现一个职责分离冲突。
role集合、请求与grant输出按标识排序，不依赖输入排列；输入重复排斥对目前逐项报告。

这是离线模拟协议，不读取操作系统权限、不访问真实IAM、不更改账号/ACL；
没有条件策略、通配符glob、临时会话、时间生效或修复写回。后续演进须明确政策语义。

# 离线权限漂移分析 access-diff v1

access-diff接收两份同样遵守上述契约的快照（--before旧快照、--after新快照），
两端分别独立完整校验，任一端无效即失败，不产生部分结果。比较对象是用户的实际allow能力，
不是requests、grant ID或输入中出现过的资源：requests仍按契约校验但完全不参与比较；
仅改grant/role名称、用继承重构但有效能力相同的两份快照判定为无漂移。

用户集合取两端ID并集并按ID排序；某端缺席的用户在该端视为无任何权限，
其决策记为deny/absent_user且matching_grants为空。对每个用户只判断两个变化方向：
granted（旧deny→新allow）与revoked（旧allow→新deny），每个方向至多输出一条
真实且确定性的（动作, 资源）见证，并给出两端decision/reason与全部匹配grant来源；
某方向不存在变化时明确输出空数组。

为在不枚举无限路径的前提下保证完备，探测宇宙由两端规则确定性生成：规则中的精确动作
与精确资源直接纳入；动作通配符*补一个两端均未出现过的具体动作；末端/*前缀同时补
其不覆盖的父目录（边界）与一个确定性具体子路径；全局资源*补一个未出现过的具体路径。
因此通配符引入或撤销的、输入中从未出现的动作/路径漂移同样会被见证。
继承闭包、deny优先、全局*与末端/*的匹配语义与上文完全一致（复用同一匹配函数）。

输出报告绑定两份输入的原始字节SHA256（before_sha256/after_sha256）；
仅重排数组不改变业务结果，只改变对应字节哈希。报告与输入路径必须两两不同且拒绝符号链接；
校验或发布失败时退出码为2并原子保留旧报告，绝不覆盖任一输入。
发布成功的报告是可独立读取的JSON，同输入重跑字节稳定。

# 权限事件账本 access-ledger v1

access-ledger把权限目录维护为SQLite事件账本：从空策略起步，逐批导入NDJSON事件，
并按双重截止投影回上述五字段策略文档。仅用一个SQLite文件，不访问网络或外部服务。

事件每行一个JSON对象（NDJSON，UTF-8，<=8MB，单次导入<=20000条，空行忽略，拒绝重复键与非有限数值），
字段恰好为event_id、kind、id、at、op、value：event_id与id为标识符；kind为role/user/grant；
at为非负整数生效时刻（<=2^63-1）；op为upsert/delete。upsert的value沿用现有对象结构
（role:{id,inherits}、user:{id,roles}、grant:{id,role,action,resource,effect}）且value.id必须与事件id一致；
delete的value为null，删除不存在的对象为空操作。事件的规范化内容指JSON键序规范化、
且role.inherits与user.roles视为集合（排序后比较）；同一event_id重投同规范化内容被忽略，
重投异内容拒绝；不同event_id占用同一(kind,id,at)时刻即冲突拒绝（即使内容相同）。

每次ingest把整份文件作为一个原子批次提交：批次号从1起严格递增，批次与事件在同一SQLite事务中落库，
进程崩溃或重启后不会出现半批数据。全部事件都是重投时不产生新批次（status=replayed），
否则提交新批次（status=committed，含ingested/ignored计数）。事件可乱序、可迟到（at可小于既有事件）。

批次提交前必须验证可见版本（截至本批的全部已提交事件）在每一个新事件可影响的生效边界上的投影：
边界为不早于本批最早at的全部事件生效时刻，每个边界投影都须通过现有策略校验（load_policy的
角色闭包、用户赋权、授权规则与exclusions校验），而不是只验最终态；任一边界失败即整体回滚事件、
批次与投影，退出码2。因此短暂悬空引用或继承环即使最终被后续事件修好，该批仍被拒绝。
更早边界的投影只依赖已验证的既有历史，不受新事件影响，无需重验。

snapshot按生效时刻（--at，缺省不限）与已提交批次（--batch，缺省最新，0为空策略）双重截止投影：
仅取批次号不超过截止的事件中at不超过截止的事件，每个(kind,id)对象取最后一条生效事件
（upsert即在、delete即不在），输出roles/users/grants按id排序、inherits/roles排序的
五字段策略文档，exclusions与requests恒为空数组，可直接作为access-audit/access-diff的输入。
批次截止使旧批次查询永不受后续导入影响，同一查询重跑字节稳定；任一（batch,at）查询的结果
都等于某个已验证边界或空策略的投影。--batch超出已提交范围、--at越界、输出与库路径相同或
输出为符号链接均拒绝，退出码2；ingest的--db与--input不得相同。原access-audit与access-diff
命令及参数保持不变。

# 批量请求审计 access-audit --requests-ndjson v1

access-audit新增可选的--requests-ndjson模式：策略仍由--source提供并完全按上文契约校验
（五字段齐全、角色闭包、未知引用与重复ID拒绝），但其requests必须为空数组；请求改由
NDJSON文件逐行提供。不传--requests-ndjson时命令行为与单文件模式完全一致。

请求文件每行一个JSON对象（NDJSON，UTF-8），结构沿用契约的具体请求：字段恰好为
id/user/action/resource，拒绝重复键与非有限数值；每行内容<=8KiB（不含行尾换行），
空行忽略，请求总数<=1000000，ID全局唯一（重复ID即失败，即使重复出现在末行）。
user必须存在，action与resource不得含*（请求必须具体）。

输出为NDJSON：首行{"schema_version":1,"policy_sha256":...,"requests_sha256":...}，
两个SHA256分别绑定策略文件与请求文件的原始字节；随后按请求ID排序每行一条决策，
字段与单文件模式analyze的请求项完全一致（decision/reason/matching_grants，
被deny压过的allow来源照样列出）；末行{"total":N,"separation_conflicts":[...]}
给出请求总数与职责分离冲突（口径同单文件模式，exclusions只告警不改变决策）。

继承闭包、deny优先、精确/全局*/末端/*的路径边界语义与单文件模式完全相同（同一匹配规则）；
实现按(action,resource)字面模式对grant建索引，每个请求只考察其具体动作与资源可命中的
少量桶，候选匹配次数随请求数与真实命中增长，不随请求数×授权数乘积增长，绝不逐请求
扫描全部授权。排序、去重、哈希与发布全程有界内存：请求经分块排序落临时文件后归并去重，
1百万请求×5000稀疏授权的峰值RSS不超过128MiB（允许临时磁盘）；临时文件无论成败均清理。
任何校验或发布失败退出码2并原子保留旧报告；source/requests/output两两不同，
output拒绝符号链接。成功时stdout输出{"schema_version":1,"requests":N,"candidate_matches":M}
摘要，同输入重跑报告字节稳定。

# 离线最小代价职责分离修复 access-repair v1

access-repair接收一份遵守上述契约的策略快照（--source）与一份修复方案（--plan），
离线计算最小代价的职责分离修复：只删除方案列出的候选边，保留全部用户/角色/授权，
输出可直接审计的修后五字段策略。两端输入各自独立完整校验，任一无效即失败。

方案为单个JSON对象，字段恰好为edits与protect。edits至多24条，每条字段恰好为
id/kind/source/role/cost：id为编辑标识且全局唯一；kind=assignment表示删除source用户的
直接role，kind=inherits表示删除source角色继承的父role；cost为正整数（<=10^9）。
候选边必须真实存在于源策略（assignment的source为用户且直接拥有role，inherits的
source为角色且直接继承role），按(kind,source,role)不重复。protect为具体请求数组
（至多10000条，结构同契约请求：id/user/action/resource，id唯一，user必须存在，
不得含通配符），修复后必须全部仍为allow。

修复语义：从候选边中选择一个子集删除，其余对象一律保留。修后策略须同时满足：
(1) 全体用户的有效角色不再违反任何exclusions职责分离约束；
(2) protect中每个请求的决策仍为allow；
(3) 相对原策略，任何用户在任何合法(动作,资源)上都不得新增allow——尤其不得因删除
携带deny的角色而把deny变成allow（deny撤销不放权）。该判定复用access-diff的确定性
探测宇宙（同一匹配函数），通配符引入的、输入中从未出现的动作与路径同样被覆盖。
注意删除只能收缩有效角色：protect在原策略中即非allow时无解；revoke（allow变deny）
始终允许。

优化目标按字典序精确全局最优：先最小化总cost，再最小化删边数，再最小化排序后的
候选id序列（字符串字典序）。实现为分支限界精确搜索，禁止贪心，也不枚举2^N份完整
策略：正cost下按当前代价裁剪；冲突在删光全部剩余候选边后仍存在则子树不可行；
protect一旦被破坏即单调不可恢复；某deny覆盖的（动作，资源）已丢全部deny角色而
allow角色在最大剩余删除下仍存活，则整棵子树必然放权（doomed）；每个未解冲突
至少需要一条通往冲突角色路径上的剩余候选边，取两两不相交约束族的最小边cost之和
作为完成代价下界；单条即破坏protect或使全部超集doomed的边预先剔除。源策略已满足
全部约束时最优解为空集（total_cost为0，selected_edits为空数组）。

无解时明确失败：stderr给出具体原因（protect在原策略即非allow、候选边无法修复的
具体冲突、或全部约束无法同时满足），退出码2并原子保留旧报告。成功报告含
schema_version/source_sha256/plan_sha256（绑定两份输入原始字节）/selected_edits
（排序后的选中id）/total_cost/policy（修后五字段策略：roles/users/grants按id排序、
inherits/roles排序，exclusions/requests沿用源文档），可直接作为access-audit与
access-diff的输入（用access-diff对比源策略可复核"无新增allow"）。同输入重跑字节
稳定；source/plan/output两两不同，output拒绝符号链接。原access-audit、access-diff、
access-ledger命令及参数保持不变。
