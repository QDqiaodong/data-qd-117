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
