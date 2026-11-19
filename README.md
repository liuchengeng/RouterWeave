# RouterWeave

RouterWeave reconstructs application activity and smart-home operations from encrypted traffic observed at a home router. Its two case studies use these activity histories to estimate cross-platform Screen Time and appliance energy consumption.

## Architecture

- **Traffic observation.** Router captures provide packet timing, size, direction, and connection information. DNS records and TLS handshakes supply service identifiers when available.
- **Activity recognition.** A window-based model classifies sustained application activity across a device’s connections. For IoT operations, a device-specific localizer selects the packets associated with an event, and a shared classifier assigns its label.
- **Applications.** Screen Time aggregates activity predictions into intervals. Appliance energy estimation combines the time spent in each inferred state with its power profile.

## Repository structure

- [Data collection and ground truth](routerweave/collection/README.md)
- [Traffic processing](routerweave/traffic/README.md)
- [Application activity recognition](routerweave/recognition/activity/README.md)
- [IoT operation recognition](routerweave/recognition/iot/README.md)
- [Screen Time and appliance energy estimation](routerweave/applications/README.md)
- [Comparisons, ablations, and router benchmarks](routerweave/evaluation/README.md)

The IoT classifier was trained on the available subset of planned recordings. Day four of the energy evaluation used replayed data.
