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

## 镜像交付链（image_release）

`image_build.record` / `image_delivery.provisional` 是事故期的临时账：前者把**源码字节摘要**当成镜像摘要，后者只比较客户提交的字符串，因此同源码、异编译器的 B1/B2 会共享“已接受”身份。`cloudcourt/image_release.py` 在不改写旧账的前提下补上可复核的完整链路（`ir_` 前缀表）：

- `pin_manifest` 把源码、依赖锁（逐依赖摘要）、编译器身份/摘要、构建参数、**真实镜像字节摘要**与签发主体分别固定，`manifest_digest` 覆盖全部；同源码异产物得到不同身份。`verify_manifest_inputs` 用重新提交的真实字节复核，依赖被同名替换会报 `dependency_digest_mismatch`。
- `attest_reproduction` 对跨机/重试重现只认真实候选字节；只有日志或声称摘要时结论是 `log_claim_insufficient`，不会记成字节相同。
- `publish_release` 用签发主体密钥做 HMAC 签发，带 `not_before/expires_at` 与客户/动作授权范围；`record_download` 必须哈希实际安装包并复核签名有效期、范围和撤回状态，下载成功只到 `downloaded`。
- `attempt_install` 从分区缓存按坐标取包、重算字节、查撤回状态与离线撤销证据包，拦住污染坐标（`cache_coordinate_mismatch`）、毒化别名和已撤回摘要的新安装。
- 设备用各自证明密钥对启动测量回执签名（`attest_measurement` / `record_measurement`）；`accept_delivery` 只有在真实字节下载、签名有效、范围匹配、测量镜像摘要与订单一致、且测量配置身份等于客户认可身份时才完成交付，并更新按客户的当前指针。
- `correct_order` 只追加不可变更正并可开替换订单；原订单、原下载与临时验收行保留。`audit_order_chain` 串起源码重算、清单、下载摘要与逐机启动测量，给出 `download_runtime_consistent`。
- `withdraw_release` 是“阻断新安装”的原子边界：必须存在字节已在缓存中复核可用的回退发行、受影响客户的业务窗口，离线设备还必须有可预置的签名撤销证据包；任一不满足则整笔不提交。`require_accepted_fallback=True` 进一步要求该设备已有回退版的已验收交付，对应“B 离线时不得先撤销 B1 通用程序”。`plan_withdrawal` 只计算该边界。撤回不删测量事实；`withdrawal_progress.safely_withdrawn` 只有在每台原受影响设备都测到并验收回退字节后才为真。迟到验收得到 `acceptance_blocked_withdrawn`，离线重联仍报旧摘要只记录事实，撤回版不会重新成为当前发行。
- 缓存分 `shared` 与 `customer:<id>` 内容寻址分区：客户密钥/配置/策略禁止写入 shared，写入字节会做泄密标记扫描；`audit_shared_cache` 重算所有 blob、查别名漂移/毒化与密钥策略泄漏；跨租户读取返回 `cache_scope_denied`。
- `customer_view` / `fleet_view` / `device_view` 给出每户每机真实运行摘要、配置身份、在线状态与补救状态；`ir_global_pointer` 仅作对照，单一 latest 不能代表 A（B1 已纠正验收）与离线 B（仍跑 B1）的不同事实。
- 两种产品架构走同一条证据链，差异由 `architecture_plan(mode)` 说明：`common` 用同一通用镜像 + 每户独立签发/轮换/撤销的配置信封，撤销粒度是通用摘要加配置代次，shared 只放通用字节；`dedicated` 向每户签出嵌入其策略的独立镜像，身份/测量/撤销都按该户真实摘要，镜像只进 `customer:<id>` 分区。模式本身不能替代任何测量或撤回检查。

测试 `tests/test_image_release.py` 覆盖同源码异编译器、依赖污染、密钥进入共享缓存、跨租户缓存、下载/启动不一致、污染坐标、A 的更正与重装验收、离线 B、密钥轮换宽限窗、签名/配置到期、越权范围、坏签名、撤回后迟到验收、离线重联、回退缺失/过期/无字节、严格“已验收替代”边界、回退成功以及两种架构的端到端差异。运行：

```sh
python -B -m unittest discover -s tests -v
```
