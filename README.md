# RouterWeave

RouterWeave uses router-visible network traffic to infer sustained application activity and short IoT operations. These predictions support two case studies, Screen Time and appliance energy estimation.

## Run from the repository root

With Python 3.12, run either of these commands using only the standard library.

```sh
python -m routerweave traffic routerweave/traffic/examples/dns_ttl.pcap --device sensor --ip 192.0.2.10 --summary
python -m routerweave evaluate comparison
```

The first command extracts six device packets from a synthetic eight-frame capture. The second recomputes the recognition comparisons from the included experiment records. Run `python -m routerweave --help` to list commands. File arguments are relative to the current directory. Each module guide gives its own dependencies and commands to run from that module's directory.

## Repository layout

| Module | Inputs and outputs |
| --- | --- |
| [Collection and ground truth](routerweave/collection/README.md) | Captures traffic and synchronized activity evidence on Android, iOS, Windows and smart-home devices. Includes hardware setup and an offline event example. |
| [Traffic processing](routerweave/traffic/README.md) | Reads a classic PCAP and device addresses. Emits device-relative packets or flows with observable service metadata. |
| [Application activity recognition](routerweave/recognition/activity/README.md) | Prepares labelled windows from recordings, fits a six-class model and predicts activity every five seconds. |
| [IoT operation recognition](routerweave/recognition/iot/README.md) | Reads normalized transport units, locates candidate operations and classifies them for a known device. Includes the study classifier and a smart-light inference example. |
| [Case studies](routerweave/applications/README.md) | Converts timed predictions into Screen Time intervals or integrates an appliance power profile over inferred states. |
| [Evaluation](routerweave/evaluation/README.md) | Recomputes comparisons, ablations, latency and resource metrics from frozen records. Includes the native router replay programs. |

## Scope of reproduction

The collection plans describe intended acquisitions. The IoT model was trained on the subset available at fitting time. Repeating the original fits requires the original recordings and splits. The included examples exercise the documented interfaces, and the evaluation tables support rescoring the recorded experiments. In the appliance energy study, day four used replayed data.
