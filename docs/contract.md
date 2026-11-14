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
