# data-qd-117 · 权限继承审计

Explainable role inheritance and deny-overrides access audit。业务输入、计算和当前边界详见 [数据契约](docs/contract.md)。

## 安装与演示

Python >=3.11，运行和测试仅用标准库；先确认 `python3 --version`。
每仓建立独立环境，构建工具锁版本。首次安装无公共缓存时可能联网；业务运行不访问网络。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-build.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps .
.venv/bin/python -m pip check
.venv/bin/access-audit --source fixtures/input.json --output run/report.json
.venv/bin/python -m unittest discover -s tests -v
```

本地已有wheel时，安装构建工具可加 `--no-index --find-links <公共wheel缓存目录>`。
修改源码后重新安装。本仓不共享其他仓环境，不依赖Docker、外部账号或持续服务。

输入JSON最多8MB，拒绝重复键、非有限数值和未定义字段；源字节SHA256随结果保留。
输出是可独立读取的JSON；成功后原子替换，输入/计算失败退出2并保留旧报告。
输入和输出不得相同，输出符号链接拒绝。单操作者批处理，不承诺并发发布或断电恢复。
同输入重跑不累加。测试使用临时目录，运行产物在忽略的run/。

src/access_audit/model.py 为业务模型，相关算法模块独立组织；common.py 提供受限JSON及报告发布，
cli.py 衔接数据链路。fixtures 为明确自制样例，代码与样例采用MIT许可。

## 离线权限漂移分析 access-diff

面向数据目录管理员的离线能力漂移命令，沿用同一份JSON契约，两端快照独立校验：

```sh
.venv/bin/access-diff --before run/old.json --after run/new.json --output run/drift.json
```

按用户ID并集比较实际allow能力（缺席用户视为无权限，记deny/absent_user），
每用户的granted（新增）与revoked（撤销）方向各至多一条确定性的动作/资源见证，
含两端决策与匹配规则来源；无变化的方向明确为空数组。规则改名、继承重构但能力等价时不误报。
报告绑定两份原始字节SHA256，数组重排不影响业务结果；任一端无效或发布失败退出2并保留旧报告，
输出与两个输入路径两两不同且拒绝符号链接。语义与报告结构见 [数据契约](docs/contract.md)。
原 access-audit 命令与参数保持不变。

## 权限事件账本 access-ledger

把权限目录维护为单个SQLite事件账本，从空策略起步，逐批导入NDJSON事件，并按需投影回五字段策略：

```sh
.venv/bin/access-ledger ingest --db run/ledger.db --input fixtures/events.ndjson
.venv/bin/access-ledger snapshot --db run/ledger.db --output run/policy.json
.venv/bin/access-ledger snapshot --db run/ledger.db --batch 1 --at 100 --output run/policy-b1.json
.venv/bin/access-audit --source run/policy.json --output run/report-from-ledger.json
```

事件含event_id、kind(role/user/grant)、id、at(非负整数生效时刻)、op(upsert/delete)、value；
upsert沿用现有对象结构且ID一致，delete的value为null，删除不存在对象为空操作。每次导入原子产生
递增批次；同event_id同规范化内容忽略、异内容拒绝，纯重投不增批次；同kind/id/at的不同事件冲突拒绝。
事件可乱序、迟到；批次提交前对可见版本的每个受影响生效边界逐一通过现有策略校验（不只验最终态，
短暂悬空引用/继承环即使最终修好也整批回滚），任何失败回滚事件、批次与投影，进程重启后无半批数据。
snapshot按生效时刻与已提交批次双重截止投影，各对象取最后生效事件，输出五字段策略
（exclusions/requests为空），旧批次查询永不受后续导入影响。语义细节见 [数据契约](docs/contract.md)。
原 access-audit、access-diff 命令与参数保持不变。

## 批量请求审计 access-audit --requests-ndjson

面向百万级请求的批量模式：策略文件不变（其requests须为空数组），请求由NDJSON文件逐行提供，
输出为NDJSON报告——首行绑定策略与请求原始字节的双SHA256，随后按请求ID排序逐条给出决策与
完整匹配来源（含被deny压过的allow），末行给出请求总数与职责分离冲突：

```sh
.venv/bin/access-ledger snapshot --db run/ledger.db --output run/policy.json
.venv/bin/access-audit --source run/policy.json --requests-ndjson run/requests.ndjson --output run/report.ndjson
```

每行<=8KiB、最多一百万条、ID全局唯一；继承、deny优先与路径边界语义与单文件模式一致，
小规模结果与analyze逐条相同。grant按(action,resource)字面模式建索引，候选匹配次数不随
请求数×授权数乘积增长；排序、去重、哈希与发布全程有界内存（峰值RSS<=128MiB，允许临时磁盘，
临时资源无论成败均清理），失败退出2并原子保留旧报告。不传--requests-ndjson时原单文件模式
行为不变。语义细节见 [数据契约](docs/contract.md)。

## 离线最小代价职责分离修复 access-repair

给定策略快照与修复方案（候选删边+保护请求），精确求最小代价的职责分离修复，
输出可直接审计的修后五字段策略：

```sh
.venv/bin/access-repair --source fixtures/input.json --plan fixtures/repair-plan.json --output run/repair.json
.venv/bin/python -c "import json;json.dump(json.load(open('run/repair.json'))['policy'],open('run/repaired-policy.json','w'))"
.venv/bin/access-audit --source run/repaired-policy.json --output run/audit-repaired.json
.venv/bin/access-diff --before fixtures/input.json --after run/repaired-policy.json --output run/repair-drift.json
```

方案edits至多24条（assignment删用户直接角色、inherits删角色父角色，cost正整数，
候选边须真实且不重复），protect为必须保持allow的具体请求。只删候选边，保留全部
用户/角色/授权；修后全体用户不再违反exclusions，protect全部仍allow，且相对原策略
任何合法动作/资源都不得新增allow（deny撤销不放权）。按总cost、删边数、排序候选id
序列依次精确求全局最优（分支限界裁剪，非贪心、非2^N枚举）；无解明确报错，退出码2
并保留旧报告。报告绑定双输入SHA256、选中id、总代价与修后策略，可用access-diff复核
无新增allow。语义细节见 [数据契约](docs/contract.md)。原 access-audit、access-diff、
access-ledger 命令与参数保持不变。

## 业务与样例结果

Ada继承reader；4项请求依次allow/explicit_deny/default_deny/default_deny，并报告1项职责分离冲突。
roles.py计算继承闭包，model.py执行规则匹配和来源解释；不访问或修改真实权限。
修复样例删除Ada的auditor直接赋权（E2，总代价3），冲突消除且Q1等protect请求仍allow，
修后策略经access-diff复核无新增allow。
