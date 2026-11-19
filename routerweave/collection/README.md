# Data collection and ground truth

Run the commands from this directory in PowerShell on Windows with Python 3.11 or later. The router must support SSH and tcpdump, and the collection host must trust its SSH host key. Android collection uses ADB. The native UI adapter also requires a JDK, an Android SDK platform, and Android SDK Build Tools. iOS collection uses go-ios and WebDriverAgent.

```powershell
python -m pip install -r requirements.txt
$env:ROUTERWEAVE_ROUTER_HOST = Read-Host 'Router address'
$env:ROUTERWEAVE_SSH_KEY = Read-Host 'Path to SSH private key'
```

| Entry point | Purpose |
| --- | --- |
| `scripts/collection/collect_mobile.ps1` | Automate Android and iOS apps, record activity events, capture router traffic, and attribute packets to apps. |
| `scripts/collection/collect_windows.ps1` | Run Windows activity plans, record foreground processes and activity intervals, and optionally capture router traffic. |
| `scripts/collection/collect_iot.ps1` | Execute device operations defined in `configs/plans/` and record the observed responses. |
| `python -m collection_core --help` | Extract activity intervals and ground truth from existing records. |

The Android single-app plan for QQ Music runs for 30 minutes. Add `-Preview` to inspect the plan. For iOS, use `ios-music-single-app` and `-IosUdid`.

```powershell
$serial = Read-Host 'ADB device serial'
.\scripts\collection\collect_mobile.ps1 -CollectionTaskId android-music-single-app -AppName qqmusic -Serial $serial -RootOut runs/collection/android-music
```

Windows can record foreground processes and capture router traffic directly. Browser automation uses Edge. Native desktop apps in a plan require the corresponding window controller. The `excluded_process_roots` list is empty by default. To exclude traffic from collection tools, add their executable names.

```powershell
.\scripts\collection\collect_windows.ps1 -CollectionTaskId windows-workstation-traffic-probe -NoAutomation -DurationSeconds 15 -EnableRouterCapture -DeviceIp (Read-Host 'Local IP address on the LAN') -RootOut runs/collection/windows-probe
```

IoT plans read `${VARIABLE}` references from the environment. Device names, interface language, and selectors must match the installation. This Google Home plan collects one power-on and one power-off operation from a smart plug.

```powershell
$env:ROUTERWEAVE_MEROSS_MSS110_MAC = Read-Host 'Smart plug LAN MAC address'
.\scripts\collection\collect_iot.ps1 -CollectionTaskId iot-google-home-operations -Platform google_home -RunRoot runs/collection/google-plug -PythonModule collection.runtime.ios.iot_google_home_capture -CollectorArguments @('--plan','configs/plans/google_home_meross_plug.json','--target-valid-per-action','1')
```

## Inputs and outputs

The synthetic example runs without a device. Each JSONL event contains a timestamp with a time-zone offset, a step name, and an execution result. The sustained activity begins 2 seconds into the trace and ends at 12 seconds. The expected interval is `[[946684802.0, 946684812.0]]` in Unix seconds.

```powershell
python -B -m collection_core mobile examples/synthetic_mobile_events.jsonl --sustain-only
```

| Inputs | Interpretation |
| --- | --- |
| Mobile activity events, router PCAP, and Android UID/socket evidence or an iOS process capture | `network_capture_windows.json` lists capture intervals. The `--sustain-only` option selects intervals for successful sustained steps. Browsing captures can also include navigation. App attribution requires app-level evidence. |
| Windows foreground samples in `ground_truth.csv` and actions in `usage_windows.jsonl` | Match the target process to activity intervals by sample time. Formal single-app plans require at least 1,800 seconds with the target in the foreground. The 15-second example checks the collection path. |
| IoT device plan, state observations, command times, and traffic | `sample_windows.json` records each command, its result, time window, and validity. Traffic observed around a command establishes an association. Confirming a physical state change requires a separate observation. |

Repeat Windows collections measure duration from verifiable foreground samples. This criterion can yield different decisions for playback or idle samples accepted by manual review in earlier experiments. Each run records its process exclusion list for use in traffic comparisons. Validation runs discard raw captures after validation and retain summaries. Reproducing the paper’s results also requires the original data, recording-level splits, and downstream models.
