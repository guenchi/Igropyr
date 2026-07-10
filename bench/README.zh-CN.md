# Igropyr 基准测试工具

[English](README.md)

该工具比较两个目录名均为 `igropyr` 的干净项目副本，不会在开发工作树中写入编译产物。

```sh
RUNS=7 WARMUPS=2 MODE=express-pooled \
  ./candidate/igropyr/bench/run-ab.sh \
  /tmp/baseline/igropyr /tmp/candidate/igropyr compiled
```

默认交替运行以下场景：

- `ab -k -n 300000 -c 500`：pooled keep-alive 主验收场景
- `ab -n 10000 -c 50`
- `ab -n 50000 -c 500`
- `ab -k -n 100000 -c 500`
- `ab -n 100000 -c 1000`

结果默认写入 `/tmp/igropyr-bench-*`，也可通过 `OUT_DIR` 指定。`summary.csv` 包含吞吐中位数、变异系数和每个已完成请求的分配字节数；原始 CSV 还记录 CPU、RSS、GC 次数、GC CPU/real time 和 GC 扫描字节数。

验收条件为：baseline 和 candidate 的 CV 均不超过 5%，主场景吞吐提升不少于 8%，每请求分配下降不少于 20%，且其它场景吞吐回退均不超过 5%。`SKIP_GATE=1` 仅用于工具冒烟。

每次正式测量都会启动新 server，先对该进程发送 20,000 个 keep-alive 请求，再重置指标。可用 `RUN_WARMUP_REQUESTS` 调整；只有检查工具本身时才建议设为 `0`。

新连接场景会逐次增加监听端口，并在每对 baseline/candidate 后默认等待 30 秒，避免 macOS 较小的临时端口池和 TIME_WAIT 污染后续结果。可通过 `NEW_CONN_COOLDOWN` 调整，正式稳定性测试不建议设为 `0`。

将最后一个参数改为 `source` 可复核源码加载模式。Scheme profile 使用 `bench/build-profile.ss` 构建，在固定负载后请求 `/__bench/profile`；响应内容是生成的 profile 首页路径，Chez 会在同一位置为各源码文件生成 HTML。macOS native 调用栈可在负载期间采样：

```sh
sample SERVER_PID 10 -file /tmp/igropyr-native-sample.txt
```
