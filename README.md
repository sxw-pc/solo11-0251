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

## 在途连接与解析换代交接

解析器撤销/换代不会把此前已准入的连接改写成“从未准入”，也不会放行旧目标上的新请求。`flow` 在 `connect` 时把旧观测、解析器代次、钉住 IP 与建立时刻快照进 `flow_attempts.frame`；`handoff`（别名 `freeze`/`fence`/`resolver_handoff`）再固定换代生效时刻与新解析目标。旧钉住的新连接仍得到 `dns_identity_changed`，换代后发往旧 IP 的包由 `usage` 记为 `old_target_frozen`，不计费。

字节证据与结算回单分开留痕：`meter`/`confirm`/`counter`（及 `evidence`/`attest` 等别名）写入 `byte_evidence`，`settle` 区分回单业务时间（`marked_at`/`sent_at`）与到达时间（`at`）。客户端确认与独立出口计数器和代理回单分叉时，无争议部分立即结算，差额以有界 `held` 进入 `settlement_disputes`，无争议剩余预留通过同一授权/窗口释放；`resolve` 只补记差额，重复回执（`receipt_key` 或同流/同额/同业务时间）返回 `duplicate_receipt` 且不二次扣费。过期仲裁员得到 `resolution_denied`（`reason=arbitrator_expired`）。撤销只通过状态隔离释放一次预留，`permit release`/`flow release` 幂等且有界，不会重复释放。

窗口额度以 `quota_windows.used` 为准，争议冻结额另外反映在 `quota_windows.held`/`egress_grants.held`；旧连接结算后释放的余额由同一 `egress_grant` 上经新解析钉住的新连接共享，不需要、也不能靠超额的重复拨款补平。所有客户准入结论与支付记录只追加：原始事件在 `events`，回单更正以带符号的 `verdict_receipts`（`status='reversed'`、`balance_delta`）追加。`tests/test_resolver_handoff.py` 以第 18–22 分钟 F/IP-A/IP-B 的现场和两种合同处置覆盖撤销重放、晚到回单、双代理重试、额度临界、仲裁者过期与全量回放。
