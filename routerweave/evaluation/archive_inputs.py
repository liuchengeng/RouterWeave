"""Project the original experimental outputs to compact, portable scoring inputs."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def table(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write(path, records):
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def binary_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def label(names, code):
    if code == -1:
        return "__abstain__"
    if not 0 <= code < len(names):
        raise ValueError(f"Unknown class index {code}")
    return names[int(code)]


def comparisons(primary, external, views, output):
    base = primary / "baseline-matrix-3x4-20261030"
    public = external / "behaviot-category-action-20261031"
    records = []
    for dataset, archive, display in (
        ("screen-time", base, "RouterWeave-App"),
        ("iot", base, "RouterWeave-IoT"),
        ("behaviot", public, "BehavIoT-Dataset"),
    ):
        folder = archive / "prepared" / dataset
        meta = read(folder / "meta.json")
        names = meta["classes"]
        indices = np.array([i for i, row in enumerate(meta["rows"]) if row["split"] == "test"])
        truth = np.load(folder / "labels.npy")[indices]
        rf = np.load(archive / "results" / f"behaviot-{dataset}-predictions.npy")
        if dataset == "iot":
            import joblib

            path = external / "flowprint-iot-source-batches-20261031/predictions.joblib"
            # Only deserialize the archived, identified prediction-only file.
            require(
                binary_hash(path)
                == "cb344df02a353c5bbfa895e112602b98a5ebdf5469e0f16563ad62e9d59159fc",
                "IoT FlowPrint prediction file changed",
            )
            fp = joblib.load(path)
            fp_truth, fp_pred = fp["truth"], fp["prediction"]
            position = meta["development_positions"]
            ours = []
            for seed in (42, 43, 44):
                with np.load(
                    primary
                    / f"iot-stage2-contaminated-training-20261028/numeric/seed{seed}/probabilities.npz"
                ) as data:
                    ours.append(
                        [label(names, y) for y in data["development"][position].argmax(axis=1)]
                    )
        else:
            fp_dir = (
                external / "flowprint-four-datasets-20261031/screen-time"
                if dataset == "screen-time"
                else public / "flowprint/behaviot"
            )
            with np.load(fp_dir / "predictions.npz") as data:
                fp = {"indices": data["indices"]}
                fp_truth = [label(names, y) for y in data["truth"]]
                fp_pred = [label(names, y) for y in data["prediction"]]
            if dataset == "screen-time":
                by_source = {(r["source_id"], round(float(r["end"]), 6)): r for r in views}
                ordered = []
                for i in indices:
                    identity, end = meta["rows"][i]["source"].rsplit("@", 1)
                    ordered.append(by_source[identity, round(float(end), 6)])
                require(
                    [r["label"] for r in ordered] == [label(names, y) for y in truth],
                    "Application labels or alignment changed",
                )
                ours = [[r["pred_joint"] for r in ordered]]
            else:
                predictions = np.load(
                    public / "results/numeric-film-behaviot/seed42-predictions.npy"
                )
                ours = [[label(names, y) for y in predictions]]
        require(
            np.array_equal(indices, fp["indices"])
            and list(fp_truth) == [label(names, y) for y in truth],
            f"{dataset} test split differs",
        )
        require(
            all(len(v) == len(indices) for v in (rf, fp_pred, *ours)),
            f"{dataset} missing predictions",
        )
        for j, i in enumerate(indices):
            records.append(
                dict(
                    dataset=display,
                    sample=int(i),
                    truth=label(names, truth[j]),
                    RouterWeave=ours[0][j],
                    BehavIoT=label(names, rf[j]),
                    FlowPrint=fp_pred[j],
                    seed43=ours[1][j] if len(ours) > 1 else "",
                    seed44=ours[2][j] if len(ours) > 1 else "",
                )
            )
    proxy = external / "itc-behavior8-baselines-20261031"
    split = read(proxy / "split.json")
    names = split["classes"]
    rows = [r for r in split["rows"] if r["split"] == "test"]
    arrays = {}
    for method, source in (
        ("RouterWeave", external / "itc-behavior8-screen-25epochs-20261031/screen"),
        ("BehavIoT", proxy / "behaviot"),
        ("FlowPrint", proxy / "flowprint"),
    ):
        with np.load(source / "test-predictions.npz") as data:
            require(
                np.array_equal(
                    data["indices"],
                    [i for i, r in enumerate(split["rows"]) if r["split"] == "test"],
                ),
                "ITC split mismatch",
            )
            require(
                np.array_equal(data["truth"], [r["label"] for r in rows]), "ITC proxy labels differ"
            )
            arrays[method] = [label(names, y) for y in data["prediction"]]
    for i, row in enumerate(rows):
        records.append(
            dict(
                dataset="ITC-Net-Blend-60",
                sample=row["window_id"],
                truth=label(names, row["label"]),
                **{k: v[i] for k, v in arrays.items()},
                seed43="",
                seed44="",
            )
        )
    write(output / "classification.csv", records)


def views_and_events(primary, output):
    views = table(primary / "section422-complementarity-discovery-20261101/windows.csv")
    conditions = table(primary / "section422-physical-scenarios-20261101/observables.csv")
    captures = {}
    records = []
    for r, c in zip(views, conditions, strict=True):
        require(
            all(r[k] == c[k] for k in ("index", "source_id", "end", "label")),
            "Cohort/window identity differs",
        )
        records.append(
            dict(
                sample=r["index"],
                capture=captures.setdefault(r["source_id"], len(captures)),
                truth=r["label"],
                traffic_only=r["pred_traffic_only"],
                service_only=r["pred_service_only"],
                joint=r["pred_joint"],
                buffered_media=int(c["A_follow_on"] == "True"),
                ambiguous_services=int(c["B_live_role_nonlive"] == "True"),
            )
        )
    write(output / "views.csv", records)
    root = (
        primary
        / "section421-input-construction-numeric-sweep-20261031/candidate-matched-classifiers/time-constrained-events"
    )
    protocol = read(root / "protocol.json")
    events = []
    for arm in protocol["methods"]:
        for tolerance in protocol["time_tolerances_seconds"]:
            records = read(root / arm / f"{tolerance:g}s/source-results.json")
            require(
                len({r["source_id"] for r in records}) == protocol["sources"],
                "Event source count differs",
            )
            for i, row in enumerate(records):
                hits = sum(m["truth"] == m["prediction"] for m in row["matches"])
                require(
                    hits == row["tp"]
                    and all(abs(m["time_error_seconds"]) <= tolerance for m in row["matches"]),
                    "Invalid association",
                )
                events.append(
                    dict(
                        arm=arm,
                        tolerance_s=tolerance,
                        source=i,
                        tp=hits,
                        outputs=row["accepted_outputs"],
                        references=row["references"],
                    )
                )
    write(output / "events.csv", events)
    return views


def efficiency(primary, output):
    base = primary / "section413-efficiency-20261031"
    latency = base / "recognition-latency-v6"
    records = []
    for filename, summary, final in (
        ("latency-observations.csv", "results.json", False),
        ("rf-window-action-observations.csv", "rf-window-results.json", True),
    ):
        require(
            binary_hash(latency / filename) == read(latency / summary)["observation_csv_sha256"],
            "Latency records changed",
        )
        for r in table(latency / filename):
            records.append(
                dict(
                    mode="iot-rf-final-window" if final else r["mode"],
                    seed=r["seed"],
                    repeat=r["repeat"],
                    input=r["input"],
                    status=r["status"],
                    onset_s=r["reference_start_seconds"],
                    decision_s=r["decision_seconds" if final else "output_seconds"],
                )
            )
    write(output / "latency.csv", records)
    protocol = read(latency / "protocol.json")
    rf = latency / "behaviot-models"
    devices = read(rf / "configuration.json")["devices"]
    required = sorted(
        {devices.index(r["device"]) for r in protocol["iot_actions"] + protocol["iot_background"]}
    )
    models = {
        "app-rw": [base / "weights.bin", base / "normalizer.bin"],
        "app-fp": [
            base / "native-flowprint-screen-time.bin",
            base / "native-baseline-labels-screen-time.json",
        ],
        "iot-rw": [latency / "models-seed42.bin", latency / "native-labels.json"],
        "iot-rf": [rf / "configuration.json", *[rf / f"device-{i:03d}.bin" for i in required]],
    }
    bins, processes = [], []
    models["iot-rf-final-window"] = models["iot-rf"] + [latency / "rf-labels.txt"]
    # The peak is taken across recorded process runs. No extrapolation across model loads.
    for mode, files in models.items():
        peak = 0
        final = mode == "iot-rf-final-window"
        folder = latency / ("rf-window-measurements" if final else "measurements")
        prefix = "iot-rf" if final else mode
        for path in sorted(folder.glob(f"{prefix}-*-seed*.jsonl")):
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 8192))
                summary = json.loads(stream.readlines()[-1])
            require(summary["type"] == "summary", f"Missing process summary in {path.name}")
            peak = max(peak, float(summary["peak_rss_mib"]))
            processes.append(
                dict(
                    mode=mode,
                    run=path.stem,
                    cpu_s=summary["cpu_seconds"],
                    wall_s=summary["wall_seconds"],
                    rss_mib=summary["peak_rss_mib"],
                )
            )
        require(peak > 0, f"No RSS samples for {mode}")
        for path in files:
            bins.append(
                dict(mode=mode, file=path.name, file_bytes=path.stat().st_size, rss_mib=peak)
            )
        if mode == "app-rw":
            index = read(base / "full-pipeline/results.json")["runtime_metadata"][
                "embedded_service_index"
            ]
            bins.append(
                dict(
                    mode=mode,
                    file="embedded_service_index",
                    rss_mib=peak,
                    file_bytes=index["array_bytes"] + index["distinct_string_bytes"],
                )
            )
    write(output / "footprint.csv", bins)
    write(output / "processes.csv", processes)
    old = base / "recognition-quiet2-v4/measurements"
    extension = primary / "routerweave-capacity-limit-20261106"
    rounds, trials = [], []
    for n in (2, 4, 8, 16, 32, 48, 54, 64):
        path = old / f"{n}-0.jsonl" if n <= 32 else extension / f"measure-{n}.jsonl"
        if n > 32:
            require(
                binary_hash(path) == read(path.with_suffix(".json"))["raw_sha256"],
                "Concurrent replay changed",
            )
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                r = json.loads(line)
                if r["type"] == "round" and 30 <= r["due"] < 130:
                    rounds.append(
                        dict(
                            devices=n,
                            due_s=r["due"],
                            finish_s=r["finish_elapsed"],
                            service_s=r["service_seconds"],
                        )
                    )
        require(
            r["type"] == "summary" and r["app_streams"] == r["iot_streams"] == n // 2,
            "Invalid concurrent load",
        )
        trials.append(
            dict(
                devices=n,
                observation_s=100,
                cadence_s=5,
                warmup_s=30,
                cores=2,
                cpu_s=r["observation_cpu_seconds"],
                rss_mib=r["peak_rss_mib"],
            )
        )
    write(output / "rounds.csv", rounds)
    write(output / "capacity.csv", trials)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--primary", required=True, type=Path, help="Primary Testbed runs/modeling directory"
    )
    parser.add_argument(
        "--external", required=True, type=Path, help="External benchmark runs/modeling directory"
    )
    parser.add_argument("--output", required=True, type=Path, help="New evidence directory")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Choose a new output directory")
    with TemporaryDirectory(dir=args.output.parent) as temporary:
        stage = Path(temporary) / "evidence"
        stage.mkdir()
        views = views_and_events(args.primary, stage)
        comparisons(args.primary, args.external, views, stage)
        efficiency(args.primary, stage)
        stage.rename(args.output)


if __name__ == "__main__":
    main()
