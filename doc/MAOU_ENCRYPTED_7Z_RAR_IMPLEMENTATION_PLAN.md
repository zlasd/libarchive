# Maou Console 加密 7z / RAR 解压实现计划

状态：实现前计划  
基线：libarchive 3.8.9，`27cbc7827172698143e440801fc0ba39ccb4f1f5`  
开发分支：`codex/encrypted-7z-rar`  
调研输入：`../maou-console/docs/LIBARCHIVE-ENCRYPTED-7Z-RAR-PLAN.md`

## 1. 目标和交付边界

目标是在不改变 libarchive 流式读取模型的前提下，让 Maou Console 通过现有 read API 解压带密码的 7z、RAR5 和 RAR3/4：

- 密码继续通过 `archive_read_add_passphrase()` 或 passphrase callback 提供；
- 解密后的数据直接进入现有解压器，不生成完整明文临时包，也不把整个文件读入内存；
- 7z 同时覆盖文件数据加密和 encoded header 加密；
- RAR5 同时覆盖 file encryption record 和 archive encryption header；
- RAR3/4 覆盖非 solid 与 solid 包的数据和主头加密；
- 不新增加密写包、密码破解、RAR7 新压缩算法和首版多卷承诺。

RAR3/4 solid 不能作为“只增加解密”的普通验收项：3.8.9 reader 对所有 `FHD_SOLID` 文件都会直接返回 `RAR solid archive support unavailable`。本项目明确把旧 RAR solid 解压状态继承纳入范围，但会与 AES/KDF 补丁分开实现和提交。

## 2. 3.8.9 基线结论

### 2.1 已验证状态

- 官方 `v3.8.9` 是附注标签，实际指向提交 `27cbc7827172698143e440801fc0ba39ccb4f1f5`。
- 本地从该提交创建了 `codex/encrypted-7z-rar`。
- macOS AppleClang Debug 配置和完整构建成功。
- 当前加密相关的 14 个 reader 测试通过，其中 1 个 RAR4 solid 测试按预期跳过；这些测试验证的是“能识别并拒绝加密”，不是解密成功。
- Apple 构建已检测到 CommonCrypto/libSystem 的 SHA-1、SHA-256 等 digest backend。

### 2.2 当前能力差距

| 模块 | 3.8.9 已有能力 | 缺口 |
| --- | --- | --- |
| passphrase | 密码队列、callback、逐个尝试、ZIP 的错误文案模式 | `archive_read_add_passphrase()` 明确拒绝空字符串 |
| digest | `archive_digest` 已提供跨 backend 的增量 SHA-1/SHA-256 | 无需重复增加 digest abstraction |
| HMAC | `archive_hmac` 仅提供 HMAC-SHA1 | RAR5 需要 HMAC/PBKDF2-SHA256 能力 |
| block cipher | `archive_cryptor` 有 AES-CTR 和 PBKDF2-HMAC-SHA1 | 7z/RAR 需要无 padding 的 AES-CBC streaming decrypt；RAR5 需要 PBKDF2-HMAC-SHA256 |
| 7z | 识别 AES coder、encoded header、solid folder 和常用 coder | `setup_decode_folder()` 主动拒绝 AES；普通链最多按两个 coder 的位置处理，无法直接容纳 AES + 压缩 + BCJ |
| RAR3/4 | 识别 `MHD_PASSWORD`、`FHD_PASSWORD`、salt 和加密标记 | header/data 都无解密；所有 RAR3/4 solid 均不支持 |
| RAR5 | 识别 `HEAD_CRYPT` 和 `EX_CRYPT`，现有 solid 解压器可用 | crypt record 被跳过，header/data 读取前没有解密层 |

3.8.9 相比前期调研使用的 3.8.8，在 7z/RAR reader 中合入了大量整数检查、varint 处理和状态清理调整。实现必须直接基于 3.8.9 的现有控制流，不能按 3.8.8 的函数行号或旧状态结构移植补丁。

## 3. 总体设计

### 3.1 保持公开读取 API 稳定

reader 在需要密码时调用：

1. `__archive_read_reset_passphrase()`；
2. 反复调用 `__archive_read_next_passphrase()`；
3. 有可靠 password check 时先验证再启用解密器；
4. 候选耗尽后返回 `ARCHIVE_FAILED`。

统一错误语义：

- 未提供密码：`Passphrase required for this entry`；
- 有可靠 check value 且验证失败：`Incorrect passphrase`；
- crypto backend 缺失：`Decryption is unsupported due to lack of crypto library`；
- KDF 参数超过资源上限：单独报告参数超限；
- CRC/hash 不匹配：报告损坏，不默认归为错误密码。

7z 和仅数据加密的旧 RAR 没有在所有变体中提供可靠的密码校验值。错误密码产生的随机明文可能只在解压或 CRC 阶段失败，因此无法始终与密文损坏严格区分；此时错误必须表述为“passphrase incorrect or archive damaged”，Maou 也不能仅因为 entry 带加密标记就把任意后续错误映射成 `wrongPassword`。

空密码保持上游公开 API 语义：`archive_read_add_passphrase(a, "")` 继续返回失败，调用方通过 passphrase callback 传递空字符串。reader 必须接受 callback 返回的空密码并覆盖相应 fixture。

### 3.2 扩展内部密码学层

在 `archive_cryptor_private.h/.c` 中增加：

- AES-128-CBC 和 AES-256-CBC decrypt init/update/release，无 padding；
- PBKDF2-HMAC-SHA256；
- 与 backend 无关的 constant-time compare；
- 不会被优化掉的敏感缓冲区清零 helper。

在 `archive_hmac_private.h/.c` 中增加增量 HMAC-SHA256，仅在 reader 确实需要流式 HMAC 时使用。7z KDF 和 RAR3/4 KDF直接复用 `archive_digest_private.h` 中已有的增量 SHA-256/SHA-1。

首个可运行 backend 为 Apple CommonCrypto，但同一提交必须至少提供其他 backend 的 stub 和稳定的 `CRYPTOR_STUB_FUNCTION` 行为，避免非 Apple 构建出现链接错误。为降低长期 fork 成本，后续补齐 OpenSSL、CNG、mbedTLS、nettle 后端，并用相同测试向量验证。

所有 backend 都必须：

- 校验 key、IV、salt 和 block alignment；
- release 时清理 context、key、IV、derived key 和残留 block；
- 不在错误文案、日志或断言中输出密码和 key；
- 对指数型 KDF 参数设置可测试的上限。具体阈值在 iPhone 真机 benchmark 后确定，不直接照搬桌面工具上限。

### 3.3 7z：把 AES 作为 packed-stream transform

相关文件：`libarchive/archive_read_support_format_7zip.c`。

实现步骤：

1. 解析 `_7Z_CRYPTO_AES_256_SHA_256` properties，严格校验 cycle power、salt size、IV size 和 properties 总长。
2. 将 libarchive 收到的 UTF-8 passphrase 转成 7z 规定的 UTF-16LE 字节序列，覆盖非 BMP 字符的 surrogate pair，并检查长度溢出。
3. 用 SHA-256 iterative KDF 派生 256-bit key；特殊 cycle-power 取值单独覆盖测试。
4. 重构 `setup_decode_folder()`：根据 coder/bind pair 关系找到从 packed input 到最终 output 的链，而不是固定把 `coders[0]` 当压缩器、`coders[1]` 当过滤器。
5. 在 packed bytes 进入 LZMA/LZMA2/PPMd/Copy/BCJ 之前流式 AES-CBC 解密。AES 状态按 folder 初始化和释放，solid folder 内按格式语义复用，不跨 folder 泄漏。
6. 同一路径用于普通文件 folder 和 encoded header，避免维护两套 crypto parser。
7. 只丢弃格式定义的末尾 zero padding；folder output size、folder CRC 和 substream CRC 仍由现有路径验证。

先支持常见线性链：`AES -> Copy/LZMA/LZMA2/PPMd`，再覆盖附加 BCJ/Delta 的三节点链，最后验证 BCJ2 多输入图。遇到无法证明正确的 graph 继续返回明确的 unsupported coder graph，不能猜测 coder 顺序。

### 3.4 RAR5：header 与 data 使用两个边界明确的解密入口

相关文件：`libarchive/archive_read_support_format_rar5.c`。

文件数据路径：

1. 将 `EX_CRYPT` 从“标记后跳过”改为完整解析 version、flags、KDF count、salt、IV 和可选 check value。
2. 为当前 file/service block 保存独立 crypto state；非 solid 文件切换时清理，solid 状态与现有 dictionary 生命周期协调。
3. 在 `merge_block()`、stored-data 路径读取 packed bytes 前统一通过 CBC transform，不修改下游 bit reader 和 decompressor 对明文压缩流的假设。
4. 实现 tweaked CRC/BLAKE2 校验语义，并保持 split/service block 状态可审计；首版多卷仍可返回 unsupported。

加密 header 路径：

1. 完整解析 `HEAD_CRYPT` 并验证 password check；不能在该分支直接返回 fatal。
2. 之后每个 header 先读取 16-byte IV，再按 16-byte 边界解密一个受上限约束的 header buffer。
3. 从解密 buffer 解析 header size/type/flags，验证 header CRC 后才调用现有 `process_head_*()`。
4. 新建 reader-local 的 header cursor/consume helper；不要让现有 `read_var()` 一部分读 raw input、另一部分读 decrypted buffer。

RAR5 技术说明只公开了部分 password-check 和 checksum 细节，并明确把进一步算法细节指向 UnRAR 源码。进入实现前必须完成许可证/clean-room 决策：优先依据公开规范、标准算法和自行生成的黑盒 fixture 实现；若必须派生 UnRAR 代码，相关文件和许可证必须隔离并经发布审查，不能作为纯 BSD 上游补丁提交。

### 3.5 RAR3/4：独立 crypto context，并补齐 solid reader

相关文件：`libarchive/archive_read_support_format_rar.c`。

- `MHD_PASSWORD`：在主头之后切换到按 16-byte block 解密的 header reader，再交给现有 header CRC/parser；
- `FHD_PASSWORD`：读取 8-byte salt，执行旧式 SHA-1 KDF，生成 AES-128 key/IV，在 `rar_read_ahead()` 与 stored/compressed reader 之间解密；
- 每个 file header 重置 file crypto state，处理同一包内不同密码；
- CRC 仍基于解压后的明文计算；无可靠 check value 的数据加密不得假装能区分错误密码和损坏。

RAR3/4 solid 另立里程碑。它要求保留旧 RAR dictionary、Huffman/PPMd 和 filter 状态，且 skip 行为也必须实际解压前序 entry；这部分与密码学实现解耦，不能夹带在 AES 补丁中，但属于本项目必须完成的退出条件。

## 4. 分阶段实施与提交拆分

### P0：fixture、规范记录与基线（3-5 天）

- 记录每个 fixture 的生成器版本、完整命令、密码、预期文件 hash 和许可来源；
- 把现有“预期拒绝”测试复制/改造为缺密码、正确密码、错误密码三组断言；
- 添加公开 AES-CBC、SHA、HMAC、PBKDF2 测试向量；
- 建立 7zz/rar/unrar 仅作为测试 oracle 的差异脚本，不进入产品产物；
- 固化 3.8.9 未加密 7z/RAR/RAR5 回归结果。

### P1：通用 crypto primitive（1-2 周）

- 单独提交 secure zero 与 constant-time compare；
- 单独提交 CBC streaming；
- 单独提交 HMAC/PBKDF2-SHA256；
- CommonCrypto、stub、OpenSSL backend 和单元测试先达到 CI 可用，其他 backend 后补。

退出条件：分块输入尺寸从 1 到 64 KiB 均与一次性向量一致；错误长度、截断 block 和重复 release 不崩溃；ASan/UBSan 通过。

### P2：7z 数据加密（2-3 周）

- properties/KDF/UTF-16LE；
- 线性 coder graph 和 streaming CBC；
- Store、LZMA、LZMA2、PPMd；
- 非 solid、solid、部分 entry 加密；
- 缺密码、错误密码/损坏、截断、极端 cycle power。

退出条件：现有三个 7z encryption fixture 改为实际读取内容，新增 Unicode 密码和多个生成器 fixture，全部未加密 7z 测试无回归。

### P3：7z header encryption 与复杂 graph（1-2 周）

- encoded header 复用 P2 解密链；
- 加密文件名、目录、空文件、长路径；
- BCJ/Delta 三节点链；
- BCJ2 仅在 graph 关系和资源边界验证充分后启用。

退出条件：`-mhe=on` 的 header/data/CRC 全部验证，列目录与实际 extraction 使用同一 parser。

### P4：RAR5 数据加密（2-4 周）

- `EX_CRYPT`、PBKDF2-SHA256、password check；
- Store 和现有压缩方法；
- 非 solid、solid、service block；
- tweaked checksum 与错误分类。

退出条件：现有 RAR5 data/solid fixture 改为解密成功，RAR7 compression version 1 仍准确返回 unsupported。

### P5：RAR5 header encryption（2-3 周）

- `HEAD_CRYPT`；
- per-header IV 和 bounded decrypted-header buffer；
- 加密文件名、service/end headers；
- header CRC、错误密码和损坏测试。

退出条件：现有 encrypted-filenames fixture 可列出并提取全部 entry，畸形 header size/IV/KDF count 的 sanitizer 和 fuzz 测试通过。

### P6：RAR3/4 非 solid 加密（3-5 周）

- 旧 KDF、AES-128-CBC、密码编码；
- data encryption 与 main-header encryption；
- Store 和 reader 当前支持的压缩方法；
- 同包多密码和部分 entry 加密。

退出条件：现有 RAR4 encryption fixture 改为实际读取内容，未加密 RAR3/4 回归、CRC 和错误路径全绿。

### P7：RAR3/4 solid reader（4-8 周）

- 移除 `FHD_SOLID` 的无条件拒绝，按 archive/file 边界保留旧 RAR dictionary 和解码表；
- Store、LZ/Huffman、PPMd 与 filter 状态分别覆盖连续 entry；
- `archive_read_data_skip()` 对 solid entry 实际解码并丢弃输出，保证后续 dictionary 正确；
- solid + data encryption、solid + header encryption 和部分读取均加入回归测试；
- 非 solid reader 行为和随机访问限制不得回归。

完整核心 fork 预计 15-27 工程周。许可证调查和 fuzz 可与后半程部分并行，但不能跳过退出条件。本轮只修改 libarchive；XCFramework 和 Maou Console 切换另立后续任务。

## 5. 测试与安全门槛

fixture 最少覆盖：

- 7z、RAR5、RAR4；无加密、仅数据、数据加 header；
- ASCII、中文、日文、emoji、长密码；空密码按 API 决策覆盖；
- Store、各 reader 已支持压缩方法；solid（RAR4 除外需单列）；
- 空文件、目录、多个 entry、Unicode/长文件名、大文件；
- 错误密码、截断、bit flip、错误 salt/IV/KDF count、错误 CRC/hash；
- 1-byte 到大 block 的 input callback，seekable 与非-seekable 读取；
- `..`、绝对路径、drive path、symlink、hardlink 继续由 Maou extraction 层拒绝。

CI 分层：

1. crypto 单元测试；
2. libarchive 精确 reader 测试；
3. 全量 `libarchive_test`；
4. ASan、UBSan、integer sanitizer；
5. 7z/RAR fuzz corpus；
6. macOS arm64/x86_64、iOS device/simulator 构建；
7. MaouCore 和 UI import matrix；
8. iPhone/iPad 真机的 KDF 时间、峰值内存、取消和磁盘不足测试。

任何 KDF、header buffer、dictionary 或文件数上限都必须：使用 checked arithmetic、在分配前验证、返回可识别错误，并有边界值测试。密码、key、明文和 derived data 不得进入日志、crash metadata 或持久化存储。

## 6. 后续 Maou Console 集成注意事项（不属于本轮修改范围）

当前 Maou 仍通过 `CLibarchive` 的 `link "archive"` 使用系统库，并在 macOS 对 7z/RAR 分别走 `7zz` 与 `unar/lsar`。核心实现完成后还需要：

- 把 fork 固定为可复现的 Apple binary target，验证最终 link map 不解析到系统 libarchive；
- 处理 fork 与系统 `archive_*` 符号冲突，可采用 hidden visibility 加薄 C adapter；
- 修改空密码传递逻辑；
- 收紧 `LibarchiveExtractor.mappedArchiveError()`：当前“只要 archive 有加密 entry 且提供了密码，任何失败都映射为 wrongPassword”会把损坏和不支持算法误报为密码错误；
- 先保留外部工具 feature flag，按 7z、RAR5、RAR4 三个兼容性门逐步移除；
- 删除工具前检查打包、签名、Sandbox、App Store export compliance 和 Third-Party Notices。

## 7. 已确认的实现决策

1. RAR3/4 solid reader 是硬性范围。
2. 本轮只修改 libarchive，不修改 Maou Console。
3. RAR 实现采用 clean-room 边界，不复制或派生 UnRAR 代码。
4. CommonCrypto 与 OpenSSL 都是首版 backend；其他 backend 提供稳定 stub。
5. 保持 `archive_read_add_passphrase()` 拒绝空字符串，空密码通过 callback。
6. 无可靠 password check 时不把损坏误报为确定的错误密码。
7. 每个逻辑步骤独立本地提交，不推送、不创建 PR、不改写历史。
8. KDF、dictionary 和文件数上限根据单元测试与本地 benchmark 设定并记录。

第一批代码只做 P0 + P1，然后完成 P2/P3 的加密 7z。RAR5 在许可证门通过后继续；RAR3/4 crypto 与 solid reader 分开提交，最终以全部格式的回归和 sanitizer 通过作为完成条件。

## 8. 参考

- libarchive 3.8.9 release: <https://github.com/libarchive/libarchive/releases/tag/v3.8.9>
- libarchive encrypted 7z/RAR issue: <https://github.com/libarchive/libarchive/issues/2516>
- 7z format overview: <https://www.7-zip.org/7z.html>
- RAR 5.0 archive format: <https://www.rarlab.com/technote.htm>
