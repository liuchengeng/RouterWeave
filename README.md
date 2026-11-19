# RouterWeave

RouterWeave reconstructs a household’s device activity history from packet metadata observed at its router. An activity record identifies the device, what it was doing, and when. A video session occupies an interval. A fan switching on is recorded at a single instant, yet the resulting state can persist long after the last packet.

## Pipeline

**Capture and ground truth.** A capture at the home router provides packet times, sizes, directions, and connection identifiers across devices. DNS and TLS handshakes supply service names when visible. During collection, device logs and controller events establish independent reference labels.

**Activity inference.** For Android, iOS, and Windows, each estimate draws on 30 seconds of concurrent connections from one device, with a new estimate every five seconds. A learned reliability gate controls how strongly service metadata modifies the traffic representation. For IoT devices, a device-specific localizer selects the packets associated with a brief operation. A classifier shared across devices labels the selected exchange.

**Activity records and applications.** Screen Time joins successive estimates into activity intervals. It can report a switch immediately or wait for later observations to confirm its timing. The appliance study reconstructs operating states from directional events such as power-on and power-off, then integrates power over time in each state to estimate watt-hours. In the paper’s architecture, applications can query current activity, retrieve device histories, or subscribe to record updates. The case-study code implements interval reconstruction and energy estimation.

## Repository structure

- [Data collection and ground truth](routerweave/collection/README.md)
- [Traffic processing](routerweave/traffic/README.md)
- [Application activity recognition](routerweave/recognition/activity/README.md)
- [IoT operation recognition](routerweave/recognition/iot/README.md)
- [Screen Time and appliance energy estimation](routerweave/applications/README.md)
- [Comparisons, ablations, and router benchmarks](routerweave/evaluation/README.md)

IoT collection is incomplete. The released classifier was trained on the subset available at fitting time. The fourth day of the appliance energy evaluation is a replay.
