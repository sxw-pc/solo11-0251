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

## 物理双光路验收（fiber_acceptance）

`fiber_route.receive` 与 `circuit_activation.provisional` 只是按线路 ID 做的临时登记：两条 ID 不同的线路即使同沟、同接续盒也会被写成 `diverse`。`fiber_acceptance` 是客户真正能签收的验收闸门，直接读取这两张登记表，并把所有证据压到同一根**物理在役纤芯**上。

- 采购单、管沟占用权（wayleave）、现场纤芯标签、双端 OTDR 曲线、接续盒独立见证与在役承载测试都必须指向同一在役纤芯；指向空载备芯的证据判 `evidence_core_mismatch` / `in_service_witness_missing`。运营商名称或外皮颜色不构成分离证据。
- 管沟登记保留换基准前后的全部历史（`route_ducts` 只追加）。仅比较 `duct` 字段会误杀本应独立的北路，因此同沟只是信息级发现；真正的硬判据是稳定接续盒身份（重贴标签保留旧标签与客户通知）、双端曲线同距离反射与在役见证。
- 容量、光衰、倒换时间与客户解析探测必须在**同一验收窗口**实测：跨窗口测量判 `measurement_not_same_window`，未通光（`lit=0`）的计划线路判 `route_not_lit`，不能占用已签收保护名额。
- 两种合同交付：客户签署短窗断测且通过后给出 `permanent_accepted`（永久双光路，安装费此时才 earned）；或先交付持独立频率许可与现场通联回执的临时无线保护（`temporary_wireless`），许可到期即失效，且永不占用永久名额。`protection_state` 不存在“无线或北路”的或逻辑——断测中且无无线备份时客户状态就是 `none`。
- `install_fees`、`settlement_entries` 与临时服务分别结算；服务签收不转移产权或路权（`conveys_ownership` / `conveys_wayleave` 恒为 false）。

```sh
python3 -B -m unittest discover -s tests -v
```

