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

## 研究归属、清偿与预警（research_release）

`cloudcourt/research_release.py` 是叠在现有三份隔离材料上的**离线裁决/发布台账**，不修改真实准入 `name.py`：

- 根因关联以**具体轨迹 + 补丁差分**为据，不按摘要/哈希/症状去重：R1（伪造来源，`rc:unauthenticated-source-provenance`）与其异字节变体同根因；R2（缓存回放，`rc:missing-replay-freshness-binding`）与 R1 同症状但近因不同，二者同属“答案缺少可验证绑定”的根因族。P 只阻断 R1，Q 阻断 R1/R2 但在 `strict_legacy` 正常答案上回归。供应商更早的超时故障单单独列为先知材料，P/Q 下超时不变，不吞并可运行链。
- `real_admission_evidence()` 在隔离内存库中用具体输入跑真实 `name.run`：伪造 `source` 标签 + 更高代次会 `answer_accepted`，错误标签/旧代次分别得到 `untrusted_resolver`/`stale_dns_answer`。
- 真实租户查询只进可逆保管库（`seal_query`/`unseal_query` 角色访问）；外发通告与研究员回执只含受影响版本与盐化 HMAC 指纹，`scan_outbound` 拦截明文查询、原始轨迹、盐与攻击步骤。
- 签约/雇佣豁免/内部许可/第三方保管/发表同意与分配/发表期限/银行凭据分表对应；临时报酬仍来自 `research_award`（impact 3 × unit 10 = 30）。只有银行结算凭据使 `paid=True`，退票回到未获报酬并重开义务；奖项撤销阻断新付款但不删除已送达公告。
- 公告送达即不可变，只能用 `correct_advisory` 追加带序号更正；盐复用证据证实（`present_salt_proof`）或 P 回退（`rollback_patch`）后，用 `public_boundary`/`recompute_obligations`/`exposure_snapshot` 重算公开边界、付款义务与暴露面，历史通知保持送达事实。
- 两条合法路径：A＝分别签署内部修补许可＋独立第三方保管触发步骤＋不含真实查询的防护通告（平台获内部许可/可约定独占）；B＝双方共同发表同意＋分配确认＋隔离复验后发布 R2 良性自检方法（公开、非独占）。

```sh
python -B -m unittest tests.test_research_release -v
```

