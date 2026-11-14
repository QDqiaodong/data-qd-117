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
