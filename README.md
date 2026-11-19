# RouterWeave

RouterWeave identifies periods of application use on phones and PCs and individual operations on smart-home devices from encrypted traffic captured at a home router. The router observes packet headers and, when available, service names from DNS and TLS handshakes. Device logs and controller events provide the reference labels for the experiments.

## Recognition methods

For Android, iOS, and Windows, RouterWeave classifies 30 seconds of traffic at a time across all observed connections from one device. The model combines packet timing, sizes, and directions with the available service metadata. It produces an activity estimate every five seconds. The Screen Time study uses successive estimates to recover activity intervals and measure their duration.

A single IoT operation can span several exchanges interleaved with background traffic. A localizer trained for each device estimates the operation’s boundaries and selects the packets that belong to it. A classifier shared across devices assigns the operation label. The appliance energy study uses directional events such as power-on and power-off to reconstruct time in each state and estimate consumption in watt-hours.

## Repository structure

- [Data collection and ground truth](routerweave/collection/README.md)
- [Traffic processing](routerweave/traffic/README.md)
- [Application activity recognition](routerweave/recognition/activity/README.md)
- [IoT operation recognition](routerweave/recognition/iot/README.md)
- [Screen Time and appliance energy estimation](routerweave/applications/README.md)
- [Comparisons, ablations, and router benchmarks](routerweave/evaluation/README.md)

The IoT classifier was trained on the recordings available at fitting time, which cover part of the collection plan. The fourth day of the appliance energy evaluation used replayed data.
