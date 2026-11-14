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

## 业务与样例结果

Ada继承reader；4项请求依次allow/explicit_deny/default_deny/default_deny，并报告1项职责分离冲突。
roles.py计算继承闭包，model.py执行规则匹配和来源解释；不访问或修改真实权限。
