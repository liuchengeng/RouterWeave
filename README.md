# RouterWeave

RouterWeave reconstructs activity histories across personal and smart-home devices from encrypted network traffic observed at a home router. It uses packet timing, size, and direction together with service identifiers available from DNS and TLS handshakes.

The recognition method depends on the time scale of the activity. On Android, iOS, and Windows, applications such as video players can remain active across several connections and through quiet buffering periods. RouterWeave aggregates traffic across a device’s connections in 30-second windows and estimates the activity class every five seconds. A smart-home operation, such as switching a plug on, may produce only a few packets interleaved with background traffic. For each known IoT device, a localizer selects the packets associated with a candidate operation, and a shared classifier assigns an operation label.

## Source code

| Component | Role |
| --- | --- |
| [Data collection](routerweave/collection/README.md) | Router traffic capture and synchronized ground truth for application use and device operations |
| [Traffic processing](routerweave/traffic/README.md) | Device attribution, connection tracking, and extraction of service metadata |
| [Application activity recognition](routerweave/recognition/activity/README.md) | Window construction, recording-level data splits, model training, and inference |
| [IoT operation recognition](routerweave/recognition/iot/README.md) | Device-specific operation localization and classification of candidate packet groups |
| [Case studies](routerweave/applications/README.md) | Screen Time estimation from activity intervals and appliance energy estimation from state transitions and power profiles |
| [Evaluation](routerweave/evaluation/README.md) | Baseline comparisons, ablations, and router latency, memory, and concurrency measurements |

## Experimental data

The IoT classifier was trained on the recordings available at the time of fitting. The collection plans also cover acquisitions outside that training set. The evaluation module contains the predictions and measurement records used to recompute the reported comparisons. Day four of the appliance energy evaluation used replayed data.
