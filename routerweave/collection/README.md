# 数据采集与真值

在 Windows 上从本目录用 PowerShell 运行。安装 Python 3.11+ 和 `requirements.txt` 中的依赖。路由器需提供 SSH 和 tcpdump，采集机需已信任路由器的 SSH 主机密钥。Android 使用 ADB，原生界面适配还需要 JDK、Android SDK 平台和 build-tools。iOS 使用 go-ios 和 WebDriverAgent。

```powershell
python -m pip install -r requirements.txt
$env:ROUTERWEAVE_ROUTER_HOST = Read-Host '路由器地址'
$env:ROUTERWEAVE_SSH_KEY = Read-Host 'SSH 私钥路径'
```

| 入口 | 采集内容 |
| --- | --- |
| `scripts/collection/collect_mobile.ps1` | Android、iOS 应用自动操作、行为事件、路由器抓包和应用流量归因 |
| `scripts/collection/collect_windows.ps1` | Windows 行为计划、前台进程、活动区间和可选路由器抓包 |
| `scripts/collection/collect_iot.ps1` | 根据 `configs/plans/` 中的设备计划执行智能家居操作并记录证据 |
| `python -m collection_core --help` | 从已有记录读取行为区间和真值 |

Android QQ 音乐的单应用计划为 30 分钟。加 `-Preview` 可先查看计划。iOS 对应使用 `ios-music-single-app` 和 `-IosUdid`。

```powershell
$serial = Read-Host 'ADB 设备序列号'
.\scripts\collection\collect_mobile.ps1 -CollectionTaskId android-music-single-app -AppName qqmusic -Serial $serial -RootOut runs/collection/android-music
```

Windows 前台记录和路由器抓包可直接运行。浏览器自动操作使用 Edge。计划中的原生桌面目标需要配套的窗口控制端。`excluded_process_roots` 默认为空，需要排除采集端程序流量时，填写其可执行文件名。

```powershell
.\scripts\collection\collect_windows.ps1 -CollectionTaskId windows-workstation-traffic-probe -NoAutomation -DurationSeconds 15 -EnableRouterCapture -DeviceIp (Read-Host '本机局域网地址') -RootOut runs/collection/windows-probe
```

IoT 计划中的 `${变量名}` 从环境变量读取。设备名称、界面语言和选择器需与现场一致。以下命令按 Google Home 插座计划各采一次开、关操作。

```powershell
$env:ROUTERWEAVE_MEROSS_MSS110_MAC = Read-Host '插座的局域网 MAC 地址'
.\scripts\collection\collect_iot.ps1 -CollectionTaskId iot-google-home-operations -Platform google_home -RunRoot runs/collection/google-plug -PythonModule collection.runtime.ios.iot_google_home_capture -CollectorArguments @('--plan','configs/plans/google_home_meross_plug.json','--target-valid-per-action','1')
```

## 输入、输出与实验口径

无需设备即可运行下列合成示例。输入是手机控制器的 JSONL 事件，含带时区的时间戳、步骤名和执行结果。示例持续活动从第 2 秒开始，第 12 秒结束，预期输出为 `[[946684802.0, 946684812.0]]`，单位为 Unix 秒。

```powershell
python -B -m collection_core mobile examples/synthetic_mobile_events.jsonl --sustain-only
```

| 输入 | 输出与含义 |
| --- | --- |
| 手机行为事件、路由器 PCAP、Android UID/socket 或 iOS 进程抓包 | `network_capture_windows.json` 给出抓包区间。`--sustain-only` 只取成功持续步骤的起止时间。浏览任务可另有包含导航的抓包区间。设备级流量不能充当应用归因。 |
| Windows 前台采样 `ground_truth.csv` 与操作记录 `usage_windows.jsonl` | 按采样时间核对目标进程和活动区间。正式单应用计划要求至少 1,800 秒目标前台时间；15 秒示例仅检查采集链路。 |
| IoT 设备计划、状态观察、命令时间和流量 | `sample_windows.json` 记录命令、结果、时间窗口及有效性。仅有命令和设备流量时，最多支持“观察到命令关联流量”，不能据此认定设备已改变物理状态。 |

Windows 复采按可核对的前台证据计时。旧实验中经人工复核接纳的播放或空闲样本可能得到不同结论。进程排除名单随运行保存，比较流量前应核对名单。标记为验证用途的采集会在校验后清理原始抓包，保留摘要。本模块用于采集和生成真值，复算论文数值还需要原始数据、录制级划分和后续模型。
