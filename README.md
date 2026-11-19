# RouterWeave

*A Unified Observation Layer for Cross-Platform Activity Analysis via Home Routers*

A video can keep playing while its network connections are quiet between buffering bursts. A smart plug can remain on for hours after the brief exchange that switched it on. RouterWeave uses encrypted traffic observed at a home router to reconstruct both the activity underway on a personal device and the operations that change an appliance’s state.

## From traffic to activity

**Sustained application activity.** RouterWeave groups traffic across a device’s concurrent connections into 30-second windows, updated every five seconds. It combines packet timing, direction, and size with service information visible in DNS and TLS handshakes. The model weights that context by its reliability when distinguishing browsing, music, live streaming, short-form video, long-form video, and background activity on Android, iOS, and Windows.

**Intermittent IoT operations.** Packets belonging to one operation can span several exchanges, with unrelated traffic in between. A device-specific localizer estimates the start and end of a candidate operation and selects its member packets. A shared classifier then assigns an operation label to the selected group.

## Applications

**Cross-platform Screen Time** turns successive activity predictions into a timeline for each device. The evaluation measures how closely the reconstructed timeline follows changes in activity and how much time it assigns to each activity.

**Appliance energy estimation** uses directional operations such as power-on and power-off to reconstruct how long an appliance occupies each state. Integrating the appliance’s power profile over those intervals gives an energy estimate in watt-hours. The fourth day of the energy evaluation used replayed data.

## Repository

| Module | Contents |
| --- | --- |
| [Data collection](routerweave/collection/README.md) | Router captures and synchronized ground truth from devices and application controllers |
| [Traffic processing](routerweave/traffic/README.md) | Device attribution, connection tracking, and observable service metadata |
| [Application activity recognition](routerweave/recognition/activity/README.md) | Window extraction, recording-level splits, training, and inference |
| [IoT operation recognition](routerweave/recognition/iot/README.md) | Packet-group localization, operation classification, and a smart-light example |
| [Case studies](routerweave/applications/README.md) | Screen Time reconstruction and appliance energy estimation |
| [Evaluation](routerweave/evaluation/README.md) | Baseline comparisons, ablations, and native router latency, memory, and concurrency measurements |

The IoT classifier was fitted to the subset of planned recordings available at training time. The repository includes the fitted classifier and the prediction and measurement records used to recompute the reported comparisons. Repeating the original training experiments requires the original recordings and splits.
