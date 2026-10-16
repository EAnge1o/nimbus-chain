# NimbusChain 深度说明

## 一句话定位

> 一个**零第三方依赖**、从零实现的区块链：密码学原语、Merkle 证明、脚本解释器、
> PoW 共识与按累计工作量的分叉重组、SPV 轻客户端全部手写，并在它之上跑了一个
> 真实可用的**文档存证与验证**应用。

## 题目定位

大多数"区块链项目"实际上是"调用库的演示"：`pip install web3`，连一条测试网，
发一笔交易，界面上显示"上链成功"。从这种项目里**看不出作者是否理解
共识**——看不出为什么难度要调整、为什么主链按工作量而不是长度选、为什么
coinbase 要等 100 块才能花。

本项目把**链本身**当作研究对象，并且刻意选择最苛刻的约束：
**零第三方运行时依赖**。这意味着没有任何一行代码可以藏在库里——
`hashlib` 里的 SHA-256 也不行（我们两套实现都写了，并逐字节比对）。

与同系列项目的关系：`nimbus-kv`（Raft 一致性）与 `nimbus-db`（WAL 崩溃恢复）
覆盖分布式底层，`nimbus-infer`（NumPy-only 推理引擎）覆盖 AI 底层，本项目覆盖
**密码学 + 分布式账本**。

## 技术深度与创新点

### 1. 密码学原语全部手写，且与权威向量逐字节可比对

- SHA-256：消息填充、64 步压缩、轮常量全手写；在 55/56/63/64/119/120 等
  **填充边界**上与 `hashlib` 逐字节一致（这些长度最容易把 bit 长度字段算错）。
- RIPEMD-160：**不用** `hashlib.new('ripemd160')`——该算法在部分 OpenSSL 构建里
  已被移出默认 provider，跨平台不可靠；实现匹配 8 组官方测试向量。
- secp256k1：Jacobian 坐标、**RFC 6979 确定性 nonce**、严格 DER、**low-S 归一化**。
  签名**逐字节可复现**，因此测试可以断言具体的 r、s 值，而不只是"验签通过"。

> 现场可验证：`python -m unittest tests.test_secp256k1 -v` 里的
> `test_satoshi_nakamoto_vector` 命中的是 Bitcoin wiki 上公认的 RFC 6979 向量。

### 2. 真 sighash + 真栈式解释器，不是"对哈希签个名"

- `OP_CHECKSIG` 走完整的 legacy sighash：清空**全部**输入的 scriptSig、把当前输入的
  scriptCode 填回、拼上 4 字节 hash 类型。少了第二步，签名就能**跨输入重放**。
- 条件执行遵循完整语义：**未生效分支里的 `IF` 不弹栈**（写错就栈下溢）。
- P2SH **两阶段执行**：先验 redeem script 的哈希，再**以 redeem script 为 scriptCode**
  执行它——不是简单的"脚本 A 然后脚本 B"。
- 多签如实兼容 `OP_CHECKMULTISIG` 的 **off-by-one 弹栈**（中本聪的著名 bug，
  改了就是硬分叉），且签名必须**按顺序**匹配公钥。
- `CLTV` / `CSV` 按 **5 字节**解码——`1 << 31` 的 sequence 禁用位用 4 字节放不下。

### 3. 按**累计工作量**选择主链，而不是"最长链"

```
work(bits) = 2^256 / (target + 1)
```

演示脚本第 5 段真实构造了这个场景：

```
分支 A：4 个块、每块难度 1x  → 累计工作量 20480
分支 B：2 个块、每块难度 4x  → 累计工作量 24576   ← 更短，但胜出
```

重组过程**精确回滚**：每个已连接的块保存 undo 记录（花了哪些 UTXO、新建了哪些
UTXO），断开时逐条还原；被挤出主链的**非 coinbase** 交易交还调用方（交给交易池）。

**两条路径互相印证**：链尖扩展走增量 UTXO 集，验证分叉块走全量重放，
测试断言两者**在所有情况下完全一致**（包括重组之后）。

### 4. 共识规则只有一份实现（全节点与轻客户端共用）

`block.compute_retarget_bits` 是全节点与 SPV 轻客户端**共用的唯一实现**。
若两边各写一份，某天其中一份改了钳制顺序，链与轻客户端会**静默分叉**：
不报错，只是对同一高度给出不同 bits，然后谁也接不上谁。
`test_client_computes_difficulty_independently` 逐高度比对两者结果。

### 5. 轻客户端零信任：难度自己算，证明必须挂到已校验的头上

SPV 只存 80 字节区块头，但：

- `bits` 由客户端**按本地历史时间戳重算**，不采信对端给的难度。
- 时间戳必须大于**本地** MTP。
- Merkle 证明必须挂到**本地已通过 PoW 校验的**区块头上；给一个从未验证过的
  `block_hash`，证明再漂亮也毫无意义——此时直接抛 `SPVError`，而不是返回 `True`。

### 6. P2P：定位器 + 孤儿池（两处只有真正实现过才会踩到的坑）

- **只比高度会漏掉分叉**：两个节点高度都是 1、链尖却不同（同高度的竞争块），
  若握手只交换高度，会得出"谁都不落后"，双方永远发现不了对方的分支。
  正确做法是 **block locator**（从链尖按指数步长取一串哈希，长度 O(log n)），
  由此找出第一个共同祖先。
- **孤儿块**：接不上的区块不能直接丢（否则"广播了区块，对端却停在旧高度"）。
  先验 PoW（否则垃圾块灌满内存）→ 挂起 → 索取父块 → 父块到位后递归解开。
  更隐蔽的是：**父块可能以侧链形式到达**，所以只要块被成功保存就要继续解孤儿。

### 7. 应用层：把"可检测篡改"讲清楚

- 链上只存 `SHA-256(文件内容)`（32 字节），**不存文件本体**。
- 验证结果**分层**：`未找到` / `仅在交易池` / `已确认` / `SPV 也验过`——
  一个只返回 true/false 的接口会掩盖这些关键差别。
- 措辞严格区分「**可检测**篡改」与「防篡改」。后者会被一句话问倒。

### 8. 一个只有写测试才会发现的真实 bug

初版实现里，同高度、同收款地址的两个竞争区块会产生**完全相同**的 coinbase 交易，
于是两条分支共享同一个 txid：交易索引被覆盖、`confirmations` 算错、
UTXO 的 key 在分支间撞车。真实矿工靠 extranonce 解决，我们用
`unique_extra_nonce(prev_hash, timestamp, txids)` 修复。
**这个 bug 是被 `test_reorg_updates_utxo_and_index` 抓出来的。**

## 可验证性（可现场复现的证据）

```bash
# 1) 349 个单元测试全绿（约 16 秒）
python -m unittest discover -s tests -t . -v

# 2) 一条命令跑完整个项目：50 项断言当场自校验
python demo.py

# 3) 纯 Python 哈希 vs hashlib、ECDSA 与脚本验证耗时
python benchmarks/bench_crypto.py

# 4) 难度对照表、实际挖矿、区块验证吞吐、SPV 存储量对比
python benchmarks/bench_pow.py

# 5) 浏览器页面：现场点「存证上链」→「验证」→「篡改一个字节后验证」
python -m nimbus_chain serve --open

# 6) 两个真实节点自己收敛（开两个终端）
python -m nimbus_chain --data-dir n1 --coinbase-maturity 1 node --name n1 --port 8001 --mine --interval 2
python -m nimbus_chain --data-dir n2 --coinbase-maturity 1 node --name n2 --port 8002 --peer 127.0.0.1:8001
```

### 关键测试 ↔ 所证明的命题

| 测试 | 证明的命题 |
|---|---|
| `test_nist_vectors_pure` / `test_padding_boundaries_match_hashlib` | 纯 Python SHA-256 正确（含 55/56/63/64/119/120 填充边界） |
| `test_official_vectors`（RIPEMD-160） | 匹配 8 组官方向量 |
| `test_satoshi_nakamoto_vector` | **RFC 6979 确定性签名命中公认向量** |
| `test_signer_always_produces_low_s` | 签名始终归一化到低半区（防签名可延展） |
| `test_malformed_rejected`（DER） | 非最小编码/负数/尾部多余字节全部拒绝 |
| `test_nested_if_inside_unexecuted_branch_does_not_pop` | 条件执行语义正确（不生效分支的 IF 不弹栈） |
| `test_multisig_script_pubkey_spend` | 多签可用，且兼容 off-by-one |
| `test_multisig_out_of_order_signatures_rejected` | 签名必须按顺序匹配公钥 |
| `test_p2sh_wrong_redeem_script_rejected` | P2SH 两阶段执行正确（错 redeem 脚本被拒） |
| `test_other_inputs_scripts_are_blanked` | sighash 清空全部输入脚本（防跨输入重放） |
| `test_double_spend_in_later_block_rejected` | 双花在区块校验层被拒 |
| `test_immature_coinbase_rejected` | coinbase 成熟度规则生效 |
| `test_coinbase_overpayment_rejected` | coinbase 不得超出「补贴 + 手续费」 |
| `test_lower_clamp_engages` / `test_upper_clamp_engages` | 难度调整的 **4 倍钳制**双向生效 |
| `test_retargeted_block_is_accepted` | 挖矿者与验证者算出**同一个 bits** |
| `test_shorter_but_heavier_branch_wins` | **短而高工作量击败长而低工作量** |
| `test_utxo_matches_full_replay_after_reorg` | 重组后增量 UTXO == 全量重放 |
| `test_reorg_returns_displaced_transactions` | 被挤出的交易交还交易池 |
| `test_orphan_chain_resolves_when_ancestors_arrive` | 孤儿块递归解开 |
| `test_block_with_invalid_pow_never_enters_the_orphan_pool` | 垃圾块不能灌满内存 |
| `test_client_computes_difficulty_independently` | 轻客户端独立重算难度，与全节点逐高度一致 |
| `test_tampered_proof_rejected` | 篡改 Merkle 路径任一哈希 => 证明失败 |
| `test_reordered_proof_direction_rejected` | 交换左右方向 => 证明失败 |
| `test_fork_is_resolved_by_cumulative_work`（P2P） | **真实 TCP 双节点**按工作量重组 |
| `test_transaction_relayed_to_a_third_node` | 交易经中间节点中转 |
| `test_nodes_on_different_networks_are_disconnected` | 创世块不同 => 不同网络，立刻断开 |
| `test_tampered_document_fails_verification` | **改一个字节 => 存证验证失败** |
| 全套 `test_server.py` | 真实启动 HTTP 服务，存证/验证/SPV 端点可用 |
| `test_console.py` | 在 cp1252 等非 UTF-8 控制台下 `demo.py` 与 CLI 仍能正常输出中文 —— CI Windows 那个真实事故的回归测试 |

## 演示脚本（建议顺序，约 4 分钟）

```bash
# ① 先跑测试，建立可信度（16 秒）
python -m unittest discover -s tests -t . -v

# ② 一条命令看完全部核心机制，50 项断言自校验
python demo.py

# ③ 量化证据（讲"纯实现慢多少、为什么仍够用"）
python benchmarks/bench_crypto.py
python benchmarks/bench_pow.py

# ④ 最有视觉冲击力的一段：浏览器里现场篡改
python -m nimbus_chain serve --open
#    点「存证上链（含挖矿确认）」→ 绿色通过
#    点「验证」→ 绿色通过（展示 OP_RETURN 里的 32 字节摘要）
#    点「篡改一个字节后验证」→ 红色失败，原因写明「链上找不到这个摘要」
#    点「验证（用 SPV 轻客户端）」→ 展示 Merkle 路径与"轻客户端只存了 320 字节"

# ⑤ 网络层证据（可选，若有第二个终端）
python -m nimbus_chain --data-dir n1 --coinbase-maturity 1 node --name n1 --port 8001 --mine --interval 2
python -m nimbus_chain --data-dir n2 --coinbase-maturity 1 node --name n2 --port 8002 --peer 127.0.0.1:8001
#    两个终端的高度与链尖会自己对齐
```

**讲解节奏建议**：② 里第 5 段（重组）停留久一点——"分支 B 更短却赢了"是整个
项目最能体现理解深度的地方。

## 常见问题与回答

**Q：这不就是"最长链"吗？**
不是。选链依据是**累计工作量** `2^256 / (target + 1)` 的累加，不是区块数量。
演示脚本第 5 段构造了「2 个块、每块难度 4x」击败「4 个块、每块难度 1x」的分支。
若按长度选链，攻击者可以用低难度块堆出一条很长的伪主链。

**Q：为什么难度要调整？固定不行吗？**
固定难度下，算力增长会让出块越来越快，最终块间隔趋近于 0。难度调整把出块速度
锚定在 `target_block_time` 附近。我们的实现每 `retarget_interval` 块按窗口首尾
时间戳差调整，并做 **4 倍钳制**（防止单次异常时间戳把难度推到极端）。
`test_lower_clamp_engages` / `test_upper_clamp_engages` 用"恰好等于钳制边界"的
两种时间戳证明钳制真的生效。

**Q：为什么用 RFC 6979？随机 nonce 不行吗？**
不行——这是 ECDSA 的经典失败模式。同一个 k 签两条不同消息，私钥可以被直接解出
（PS3 就是这么被攻破的）。RFC 6979 用 HMAC 从 `(私钥, 消息摘要)` 确定派生 k，
**结构上**消灭这类事故；副产品是签名逐字节可复现，测试因此能断言具体的 r、s 值。
实现上有两处极易写错：`bits2int` 在消息长度恰好 256 位时**不能取模**，
而 `bits2octets` 才是取模的地方。

**Q：low-S 有什么用？**
数学上 `(r, s)` 与 `(r, N-s)` 都有效，但**不归一化意味着同一笔交易有多种字节表示**，
txid 因此不确定（第三方可以在不改变交易含义的前提下改 txid）。我们统一归一化到
低半区，并在 DER 解析里严格拒绝非最小编码。

**Q：你的 sighash 和 Bitcoin 一样吗？**
一样的规则、只支持 `SIGHASH_ALL`。四步：复制交易 → 清空**全部**输入的 scriptSig →
把当前输入的 scriptSig 换成 scriptCode → 拼 4 字节 hash 类型后双 SHA-256。
第二步是防跨输入重放的关键；第三步的 scriptCode 在 P2SH 下是**弹出的 redeem script**，
不是 scriptPubKey。

**Q：重组的时候账本怎么不错？**
每个连上的块保存 `BlockUndo`（花掉的 UTXO + 新建的 UTXO）。断开时**先还原花掉的、
再删除新建的**（顺序不能反：同块内后一笔交易可能花前一笔的输出）。
另外我们还保留**全量重放**路径，测试断言"增量集 == 全量重放"，
两者互为对照，杜绝静默不一致。

**Q：coinbase 为什么不能立刻花？**
否则矿工可以在同一个块里花掉自己的 coinbase，一旦这个块被重组，"花掉"的动作
连同上链的交易全部作废，可能引发连锁失效。成熟度（本项目默认 100）让矿工必须先
承受一段时间的重组风险。测试用默认成熟度验证"未成熟就被拒"，演示参数设为 1
只是为了流程能在秒级跑完——参数是演示级，**规则没有放宽**。

**Q：SPV 只存区块头，那它凭什么相信某个交易在链上？**
两件事缺一不可：(1) 区块头自带 PoW 并通过 `prev_block` 串成链，篡改任何一处都要
重做工作量证明；(2) Merkle 证明用 `log2(n)` 个哈希即可证明某笔交易被某个区块头承诺。
我们额外做了"零信任"处理：难度 `bits` 由客户端**自己按历史时间戳重算**，
时间戳必须大于**本地** MTP，且证明必须挂到**本地已校验过的**区块头上
（否则抛 `SPVError`，而不是返回 True）。

**Q：你的 P2P 真的能跑通吗？**
能，而且是真实 TCP。`tests/test_p2p.py` 里的测试启动两个真实的 asyncio 服务器
（端口 0 让系统分配），跑真实握手、真实区块传输、真实 PoW 与脚本校验，
断言它们收敛到同一条链——包括**真实分叉后的按工作量重组**与**交易经第三个节点中转**。

**Q：跟 Bitcoin Core 比怎么样？**
规则层面有四块是一致的：脚本解释器（P2PKH/P2SH/多签/CLTV/CSV）、难度调整与钳制、
按累计工作量选链、SPV 存在性证明。差别在于：我们没有 SegWit/Taproot、没有
RBF/CPFP、没有地址簿与节点发现、挖矿没做隔离。这些是**范围选择**，不是理解缺口——
`docs/design.md` 的最后一节把这些取舍逐条列出来了。

**Q：零依赖是不是噱头？**
不是。它是**可验证性的前提**：当项目里没有 `ecdsa`、没有 `web3`、没有 `python-bitcoinlib`，
`pip install` 一步都不需要，评审可以断网跑通全部证据（包括浏览器页面）。
同时它逼着我们把每层的实现都写对——否则测试立刻变红。

## 局限与后续方向

- 不做 SegWit / Taproot / RBF / CPFP；只支持 `SIGHASH_ALL`。
- P2P 无地址簿与节点发现（DNS seeds）、无 getheaders 增量同步、无限速与反女巫。
- 挖矿在 asyncio 事件循环内跑（演示规模每块十几毫秒）；生产实现应隔离到子进程。
- 持久化是可读 JSON；真实实现应改为页面文件 + WAL（可参考本仓库的 `nimbus-db`）。
- 演示难度 `pow_limit = 0x1f0fffff`（期望约 4096 次哈希），不是主网参数。
- 存证只保证「可检测篡改」，不解决文件丢失；链上不存文件本体。
- 每条取舍的理由与代价都写在 `docs/design.md` 第 9 节。

## 技术栈

Python 3.10+ / **仅标准库**；`unittest`（349 个用例，约 16 秒）；
GitHub Actions 在 Ubuntu 与 Windows 上跑 Python 3.10 / 3.12 / 3.13。
