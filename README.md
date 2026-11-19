# RouterWeave

RouterWeave is a router-side observation framework that combines cross-platform traffic collection, task-adaptive processing, and unified activity records for household applications. It uses encrypted traffic at the home router to observe sustained activities on Android, iOS, and Windows devices and discrete operations on IoT devices.

## Pipeline

**Observation units.** All devices share a single traffic observation point at the home router. For sustained activities, sliding windows capture traffic across concurrent connections. For intermittent IoT operations, a device-specific localizer groups the packets associated with each operation. Platform-specific logs and controller events supply ground truth during collection.

**Cross-layer evidence.** The activity model encodes packet timing, directional byte counts, and connection dynamics. Feature-wise linear modulation (FiLM) incorporates service context from visible protocol metadata, with a learned gate controlling its contribution. For IoT operations, a classifier shared across devices labels the packet groups selected by the localizer.

**Activity record lifecycle.** The record manager creates, updates, and closes records in a shared device history. Each record associates a device and an activity label with an interval for sustained activity or a transition time for a discrete operation. An appliance’s inferred state can therefore persist through periods of network silence.

**Application interface.** The framework defines a common interface for device discovery, current activity, historical queries, and record updates. The Screen Time case study aggregates activity intervals across platforms. The appliance energy case study integrates power over the time spent in each inferred state.

## Repository structure

- [Data collection and ground truth](routerweave/collection/README.md)
- [Traffic processing](routerweave/traffic/README.md)
- [Application activity recognition](routerweave/recognition/activity/README.md)
- [IoT operation recognition](routerweave/recognition/iot/README.md)
- [Screen Time and appliance energy estimation](routerweave/applications/README.md)
- [Comparisons, ablations, and router benchmarks](routerweave/evaluation/README.md)
