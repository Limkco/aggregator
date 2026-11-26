# 直接在 GitHub 网页端查看
打开你的 GitHub 仓库主页。

在左上角有个切换分支的下拉菜单（默认通常显示 main 或 master）。

点击下拉菜单，选择 release 分支。

你会看到里面只有两个文件：

sub.txt（经过 Base64 编码的订阅文件，专供客户端使用）

nodes.txt（明文的节点链接，带上了地理位置和延迟信息，供你肉眼查看或手动复制）

## 本地运行与测试

需要 Python 3.11 或以上版本：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

处理流程（在仓库根目录执行）：

```bash
python aggregator.py       # 可通过 GH_TOKEN 环境变量提高 GitHub API 配额
python merge_nodes.py      # 可选读取 previous_nodes.txt 合并历史节点
python filter_nodes.py
python check_active.py
```

脚本生成 `nodes.txt` 和 Base64 编码的 `sub.txt`；自动工作流将最终结果保存至当前分支的 `result/` 目录。上方 release 分支说明仅适用于已有独立发布流程的部署。

注意：在线采集和测活需要外网访问。离线回归测试不访问真实节点。WebSocket Upgrade、QUIC 版本协商以及 TCP/TLS 探测不能证明代理鉴权成功或端到端可用；Reality 等协议仍需要专用客户端进一步验证。
