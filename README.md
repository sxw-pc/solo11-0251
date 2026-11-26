# 租户出站许可与解析仲裁庭

离线租户出站控制面模拟。只裁决租户能否使用已有外部目的地、DNS 解析 IP 和用途额度；不管理域名所有权、证书或 Ingress，也不发起真实 DNS/网络请求。运行环境为 Python 3.11+ 标准库与 SQLite。

## 三个入口

- `name`：目的地档案、解析源策略和带 TTL 的 DNS 观测。档案换代、未知解析源、旧答案或隔离结果都不能钉住 IP。可疑已准入连接触发目的地复核与隔离。
- `permit`：用途合同、租户额度窗口及出站使用许可。准入前检查目的地档案与新鲜解析证据；转让冻结旧持有人，撤销隔离未结连接。
- `flow`：DNS 钉住、连接尝试、真实字节结算与可疑行为回执。许可持有人、目标 IP、期限和余额共同决定连接；超额结算拒绝，成功结算改变下次可用量。

三个入口各有独立业务状态表和正常/失败 fixture。事件 ID 重试幂等，同 ID 异内容拒绝；事件重放逐表比较当前状态。

## 运行

```sh
python -m cloudcourt demo --db demo.sqlite
python -m cloudcourt replay --db demo.sqlite
python -m unittest discover -s tests -v
```

独立入口示例：`python -m cloudcourt name --db state.sqlite --fixture fixtures/name-normal.json`。同一个数据库可依次运行 `name`、`permit`、`flow` 的正常样例；`fixtures/path.json` 创建跨系统 DNS 钉住。每个入口的 `-failure.json` 给出旧解析、超额授权或错误 IP 等反例。

测试覆盖解析代次、档案换代、额度超拨、连接结算、撤销与可疑连接导致的目的地隔离。业务结论可在 `destination_profiles`、`egress_grants`、`flow_attempts` 和原始事件中核实。

解析观测绑定解析器 ID 与代次；解析器换代或撤销后，旧 DNS 钉住不能继续授权连接。超额结算进入 `settlement_disputes`，只有与租户匹配、仍在有效期内的审计员记录才能批准纠正数额。

## 余热交付核定（heat_reconciliation）

机房把解析设备余热卖给相邻买家时，主管道总表只证明出口热量，不能证明任一买家实收。`heat_reconciliation` 把物理证据与资金事实分开保存，直到合同授权的决议把两者连接：

- 读数保留表计本地原始区间，时钟偏移归一化到统一时间线；错位边界的热量进入 `heat_uncertain_intervals`，不静默摊给任何客户。
- 支管读数按拒收通知与校准证书有效期切分，逐段归类为可证实交付、待争议热量（`buyer_rejection`、`calibration_expired`、`backfilled_reading`、`clock_skew_boundary`、`meter_over_reading`）或机房侧管损。
- 校准有效的主管道出口是硬上限：任何客户开票累计不得超过它；冷机自用热不计入买家账单；未知值不进入客户余额。
- 两种履约方式均有记录：`retest`（共同复测为最终依据，先仅按可证实量开临时账单，复测确认的增量净额补票）与 `provisional_capped`（上限临时结算，争议部分款项进托管账户，迟到复校证书只产生引用原账单/原付款的退款或补款，永不重写已送达账单）。
- 复测为最终依据后迟到的复校证书只留证、不改账；`rebuild_accounts` 从同一批物理证据重建两种决议各自合法的账，资金事实只出现在实际授权的路径下。

