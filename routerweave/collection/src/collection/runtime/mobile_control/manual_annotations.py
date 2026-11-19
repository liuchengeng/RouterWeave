"""Complete operator timeline and append-only reviews, separate from model outputs."""
from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import shutil
from datetime import datetime, timezone

from collection.runtime.capture.pcap import pcap_format
from .capture.router import parse_tcpdump_trailer
from .manual_ground_truth import read_events, segments_from_events, write_json, event_windows

SOURCE_FILES = ("capture.pcap", "collection_manifest.json", "collection_task.json",
                "manual_ground_truth/events.jsonl", "labels.csv", "network_capture_windows.json",
                "capture.pcap.tcpdump.stderr.log", "manual_event_windows.json")
GAP_POLICY = "operator_unassigned_intervals_are_no_task"
PACKET_FIELDS = ['packet_index','ts_epoch','length','captured_length','direction','ip_protocol','in_collection_interval']


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sources(root):
    return {name: sha256(root / name) for name in SOURCE_FILES if (root / name).is_file()}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def bounds(root):
    events = read_events(root)
    manifest = read_json(root / "collection_manifest.json")
    ready = next(row for row in events if row["event"] == "capture_ready")
    end = next((row for row in events if row["event"] == "capture_end_requested"), events[-1])
    if events[-1]["event"] != "capture_stopped" or end["pc_epoch"] <= ready["pc_epoch"]:
        raise ValueError("本轮尚未完整结束，无法复核或评估。")
    return ready["pc_epoch"], end["pc_epoch"], manifest


def validate_timeline(rows, start, end):
    cursor = start
    if not rows:
        raise ValueError("时间线为空")
    for row in rows:
        a, b = row["pc_start_epoch"], row["pc_end_epoch"]
        if not all(math.isfinite(x) for x in (a, b)) or abs(a - cursor) > 1e-6 or b <= a:
            raise ValueError("时间线存在空洞、重叠或无效边界")
        if row["screen_state"] not in {"on", "off", "unknown"} or not row["label"].strip():
            raise ValueError("屏幕状态或标签无效")
        if row["review_status"] not in {"pending", "recorded", "confirmed", "excluded"}:
            raise ValueError("复核状态无效")
        if row["review_status"] in {"recorded", "confirmed"} and row["label"] in {"unknown", "no_task"}:
            raise ValueError("未知行为不能确认为真值，请补标或明确排除")
        if row["review_status"] == "excluded" and not row.get("reason", "").strip():
            raise ValueError("排除时间段需要原因")
        cursor = b
    if abs(cursor - end) > 1e-6:
        raise ValueError("时间线没有覆盖整轮采集")


def original_timeline(root):
    start, end, manifest = bounds(root)
    completed = segments_from_events(read_events(root), manifest["clock_start"])
    rows, cursor = [], start
    for segment in completed:
        a, b = segment["pc_start_epoch"], segment["pc_end_epoch"]
        if a > cursor:
            rows.append(no_task_interval(cursor, a))
        rows.append({key: segment[key] for key in ("pc_start_epoch", "pc_end_epoch", "label", "app", "screen_state")}
                    | dict(review_status="pending" if segment["label"] == "unknown" else "recorded",
                           reason=segment["note"], source=segment["segment_id"]))
        cursor = b
    if end > cursor:
        rows.append(no_task_interval(cursor, end))
    validate_timeline(rows, start, end)
    return rows


def no_task_interval(start, end):
    return dict(pc_start_epoch=start, pc_end_epoch=end, label="no_task", app="",
                screen_state="unknown", review_status="excluded", reason=GAP_POLICY, source="gap")


def load_timeline(root):
    root = Path(root).resolve()
    rows = original_timeline(root)
    start, end, _ = bounds(root)
    fingerprint = None
    parent = None
    for index, path in enumerate(sorted((root / "manual_ground_truth" / "reviews").glob("*.json")), 1):
        review = read_json(path)
        if fingerprint is None:
            fingerprint = sources(root)
        if (path.name != f"{index:06d}.json" or review["revision"] != index
                or review["previous_sha256"] != parent or review["source_sha256"] != fingerprint):
            raise ValueError("原始文件或复核记录已变化，请检查来源和修订链")
        rows = review["timeline"]
        validate_timeline(rows, start, end)
        parent = sha256(path)
    # Apply the operator's current rule to untouched gaps in older reviews without rewriting them.
    return [no_task_interval(row['pc_start_epoch'], row['pc_end_epoch'])
            if row['source']=='gap' and row['label']=='unknown' and row['review_status']=='pending'
            else row for row in rows]


def revise_interval(root, *, start, end, label, app, screen_state, reason, exclude=False):
    """Replace a range, splitting its neighbors; exclusive file creation prevents lost updates."""
    root = Path(root).resolve()
    rows = load_timeline(root)
    lower, upper, _ = bounds(root)
    if not math.isfinite(start) or not math.isfinite(end) or not lower <= start < end <= upper:
        raise ValueError("修订区间必须位于本轮采集时间内")
    if not reason.strip() or len(reason) > 2000 or not label.strip() or len(label) > 160 or len(app) > 160:
        raise ValueError("请填写标签及本次确认／补标的依据（不超过 2000 字）")
    if label in {"unknown", "no_task"} and not exclude:
        raise ValueError("无法确认的区间请选择排除，并填写原因")
    revised = []
    for row in rows:
        a, b = row["pc_start_epoch"], row["pc_end_epoch"]
        if b <= start or a >= end:
            revised.append(row)
        else:
            if a < start:
                revised.append({**row, "pc_end_epoch": start})
            if b > end:
                revised.append({**row, "pc_start_epoch": end})
    revised.append(dict(pc_start_epoch=start, pc_end_epoch=end, label=label.strip(), app=app.strip(),
                        screen_state=screen_state, review_status="excluded" if exclude else "confirmed",
                        reason=reason.strip(), source="operator_review"))
    revised.sort(key=lambda row: row["pc_start_epoch"])
    validate_timeline(revised, lower, upper)
    folder = root / "manual_ground_truth" / "reviews"
    folder.mkdir(exist_ok=True)
    previous = sorted(folder.glob("*.json"))
    revision = len(previous) + 1
    value = dict(schema="manual-timeline-review-v1", revision=revision,
                 created_utc=datetime.now(timezone.utc).isoformat(),
                 previous_sha256=sha256(previous[-1]) if previous else None,
                 source_sha256=sources(root), timeline=revised)
    with (folder / f"{revision:06d}.json").open("x", encoding="utf-8") as handle:
        import os
        json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.flush()
        os.fsync(handle.fileno())
    return revised


def capture_audit(root):
    """Count every stored frame, including ARP, and require a clean tcpdump trailer."""
    path = root / "capture.pcap"
    count = truncated = 0
    with path.open("rb") as handle:
        header = handle.read(24)
        endian, _ = pcap_format(header, path)
        while record := handle.read(16):
            if len(record) != 16:
                raise ValueError("PCAP 记录头不完整")
            _, _, captured, original = struct.unpack(endian + "IIII", record)
            if len(handle.read(captured)) != captured:
                raise ValueError("PCAP 数据包不完整")
            count += 1
            truncated += captured < original
    log = root / "capture.pcap.tcpdump.stderr.log"
    text = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
    statistics = parse_tcpdump_trailer(text)
    captured, dropped = statistics["captured"], statistics["kernel_dropped"]
    errors = []
    if captured is None or dropped is None:
        errors.append("缺少 tcpdump 完整结束及丢包统计")
    elif captured != count or dropped:
        errors.append("抓包记录数不一致或路由器报告丢包")
    if truncated:
        errors.append("存在被截短的数据包")
    return dict(pcap_frames=count, truncated_frames=truncated,
                kernel_dropped=dropped, errors=errors)


def snapshot(root):
    from .validation import validate_mobile_collection
    root = Path(root).resolve()
    validation = validate_mobile_collection(root)
    start, end, manifest = bounds(root)
    rows = load_timeline(root)
    clock = manifest["clock_start"]
    # Retain the recorded initial offset; increase the guard to include the final bound.
    uncertainty = max(clock["uncertainty_seconds"],
                      abs(manifest["clock_end"]["offset_seconds"] - clock["offset_seconds"])
                      + manifest["clock_end"]["uncertainty_seconds"])
    for row in rows:
        row.update(router_start_epoch=row["pc_start_epoch"] + clock["offset_seconds"],
                   router_end_epoch=row["pc_end_epoch"] + clock["offset_seconds"])
    durations = {status: sum(row["pc_end_epoch"] - row["pc_start_epoch"] for row in rows
                            if row["review_status"] == status) for status in ("pending", "recorded", "confirmed", "excluded")}
    audit = capture_audit(root)
    errors = list(validation.core_errors) + audit["errors"]
    value = dict(schema="manual-ground-truth-timeline-v2", run=str(root), source_sha256=sources(root),
                pc_start_epoch=start, pc_end_epoch=end,
                router_start_epoch=start + clock["offset_seconds"], router_end_epoch=end + clock["offset_seconds"],
                clock_uncertainty_seconds=uncertainty, phone_ip=manifest["router"]["phone_ip"],
                duration_seconds=end-start, review_seconds=durations,
                gap_policy=GAP_POLICY,
                no_task_seconds=sum(row['pc_end_epoch']-row['pc_start_epoch'] for row in rows if row['label']=='no_task'),
                task_data_ready=not errors and not durations['pending'] and bool(durations['recorded']+durations['confirmed']),
                labels_complete=all(row["review_status"] in {"recorded", "confirmed"} for row in rows),
                review_complete=all(row["review_status"] != "pending" for row in rows),
                capture_ready=not errors, errors=errors, capture_audit=audit, timeline=rows,
                review_sha256={p.name: sha256(p) for p in sorted((root/'manual_ground_truth'/'reviews').glob('*.json'))},
                warnings=list(validation.warnings),
                legacy_end_includes_teardown=not any(e["event"] == "capture_end_requested" for e in read_events(root)))
    if manifest.get("manual_protocol"):
        points = event_windows(read_events(root), manifest)
        for point in points:
            point["clock_uncertainty_seconds"] = uncertainty
        value.update(manual_protocol=manifest["manual_protocol"], event_windows=points,
                     task_data_ready=not errors and (manifest["manual_protocol"]["mode"] == "background_observation"
                                                     or any(p["input_eligible"] for p in points)))
    return value


def write_csv(path, rows, fields=None):
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields or (list(rows[0]) if rows else []))
        writer.writeheader()
        writer.writerows(rows)


def export_snapshot(root, out):
    root = Path(root).resolve()
    value = snapshot(root)
    if not value['capture_ready']:
        raise ValueError('抓包完整性检查未通过，原始文件已保留：'+'；'.join(value['errors']))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    write_json(out/'export_manifest.json', dict(schema='manual-ground-truth-export-v2', status='writing'))
    write_json(out / "ground_truth.json", value)
    if "event_windows" in value:
        write_json(out / "event_windows.json", value["event_windows"])
        if value["event_windows"]:
            write_csv(out / "event_windows.csv", value["event_windows"])
    rows = export_rows(value)
    write_csv(out / "ground_truth.csv", rows)
    usable = [row for row in rows if row['usable_label']]
    write_csv(out / "labeled_segments.csv", usable, fields=list(rows[0]))
    shutil.copyfile(root/'capture.pcap', out/'capture.pcap')
    evidence = out/'evidence'
    evidence.mkdir()
    for name in value['source_sha256']:
        if name == 'capture.pcap':
            continue
        target = evidence/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/name, target)
    for name in ('collection_events.jsonl','collection_validation.json'):
        if (root/name).is_file():
            shutil.copyfile(root/name, evidence/name)
    for name in value['review_sha256']:
        target = evidence/'manual_ground_truth'/'reviews'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/'manual_ground_truth'/'reviews'/name, target)
    for name, expected in value['source_sha256'].items():
        copied = out/'capture.pcap' if name=='capture.pcap' else evidence/name
        if sha256(copied) != expected:
            raise ValueError('复制后的文件与原始证据不一致：'+name)
    packet_count = write_packet_csv(out, value)
    current = snapshot(root)
    if current != value:
        raise ValueError('导出期间采集或标注发生变化，保留未完成导出，请重新导出')
    manifest = dict(schema='manual-ground-truth-export-v2', status='complete',
                    capture_ready=value['capture_ready'], labels_complete=value['labels_complete'],
                    review_complete=value['review_complete'],
                    fully_labeled_ready=value['capture_ready'] and value['labels_complete'],
                    task_data_ready=value['task_data_ready'], gap_policy=GAP_POLICY,
                    no_task_seconds=value['no_task_seconds'],
                    usable_labeled_seconds=sum(row['duration_seconds'] for row in usable) if value['capture_ready'] else 0,
                    pending_seconds=value['review_seconds']['pending'], excluded_seconds=value['review_seconds']['excluded'],
                    ip_packets=packet_count, label_segments=len(usable), phone_ip=value['phone_ip'],
                    input_scope='ground_truth_intervals_with_input_eligible_true', input_pcap='capture.pcap',
                    packet_scope='continuous_capture',
                    timestamp_unit='Unix seconds', packet_clock='router',
                    label_interval='half-open [router_start_epoch, router_end_epoch)',
                    clock_uncertainty_seconds=value['clock_uncertainty_seconds'],
                    source_run=str(root), original_source_sha256=value['source_sha256'],
                    errors=value['errors'])
    (out/'README.md').write_text(
        '# 手动行为采集数据\n\n'
        'capture.pcap 是唯一的 PCAP，完整保留原始连续抓包，不拆分、不裁剪、不改时间戳。\n'
        'packets.csv 保留全部目标 IP 包；ground_truth.csv 覆盖整轮，标记任务和 no_task 空档。\n'
        '后续构造输入时，只选 ground_truth.csv 中 input_eligible=True 的时间区间；labeled_segments.csv 提供这些区间。\n'
        '将包的 ts_epoch 与标签的 router_start_epoch / router_end_epoch 对齐，单位都是 Unix 秒，区间左闭右开。\n'
        'length 是 PCAP 原始帧长度，单位字节；direction 的 in/out 以目标手机为参照。\n'
        '按操作员采集规则：无任务时段标为 no_task 并排除，不输入、不评分，不作为 background 类。\n'
        '时间轴保持连续，构造样本时不跨越被排除的空档。transition 是显式标记的任务，按自己的评估协议处理。\n'
        'packets.csv 的 in_collection_interval 只表示是否处于本轮逻辑起止时间内，不表示该包可作为任务输入。\n'
        '逻辑起止时间之外的启动／收尾包同样保留，但没有有效任务标签，不参与输入或评分。\n'
        '已有按钮标签为 recorded，无需重复确认；补标或修订为 confirmed；未知为 pending；主动排除为 excluded。\n'
        '先读 export_manifest.json：task_data_ready 表示任务数据就绪，no_task_seconds 是正常排除时长，无需补标。\n'
        'pending_seconds 仅表示显式标记为 unknown 的任务；excluded_seconds 包括无任务时段及人工排除。\n'
        'clock_uncertainty_seconds 不包含人工点击反应时间。raw 证据及每次修订保存在 evidence/。\n'
        '此导出不包含模型、特征窗口、推测或评分。\n', encoding='utf-8')
    if "manual_protocol" in value:
        observation = value['manual_protocol']['mode'] == 'background_observation'
        manifest.update(manual_protocol=value['manual_protocol'],
                        input_scope='continuous_background_observation' if observation else 'event_windows_with_input_eligible_true',
                        event_count=len(value['event_windows']),
                        complete_event_windows=sum(p['input_eligible'] for p in value['event_windows']))
        (out/'README.md').write_text(
            '# Screen Time · IoT 人工采集\n\n'
            'capture.pcap 完整保留连续原始流量；packets.csv 包含全部目标 IP 包。时间单位为 Unix 秒。\n'
            'manual_protocol 保存平台、设备、人工记录方式及预定前后窗口。IP 由操作员填写，未自动核验设备身份。\n'
            'event_windows.json / CSV 保存人工动作时间 pc_event_epoch、对齐路由器的 router_event_epoch 及前后窗口。\n'
            '包 ts_epoch 对齐 [router_start_epoch, router_end_epoch)。前后流量都完整的事件 input_eligible=True。\n'
            '窗口重叠时 overlaps_other_event=True；不可当作互相独立或只有单一事件的样本。\n'
            '标签表示操作员为触发该状态所实施的动作；state_verified=False，不能当作传感器实际状态转换的精确时间。\n'
            'clock_uncertainty_seconds 包括首尾校时误差，不包含人工同步误差或传感器响应延迟。原始 PCAP 时间戳不改写。\n'
            '连续观察模式只记录日常背景流量，没有自动状态标签。仅分析本轮逻辑起止时间内的包。\n'
            'ground_truth.csv 是原有连续任务时间线；IoT 点事件输入使用 event_windows，连续观察使用连续流量。\n'
            '原始打点、注册任务、校时与窗口证据保存在 evidence/。formal_ready=False，不自动增加正式样本数。\n',
            encoding='utf-8')
    manifest['artifact_sha256'] = {p.relative_to(out).as_posix(): sha256(p) for p in out.rglob('*')
                                   if p.is_file() and p.name != 'export_manifest.json'}
    write_json(out/'export_manifest.json', manifest)
    verify_export(out)
    return value


def packet_rows(path, value):
    """Retain every IP packet in source order; eligibility belongs to the label timeline."""
    from .capture.pcap import iter_decoded_packets
    phone_ip = value['phone_ip']
    for packet in iter_decoded_packets(path, ip_only=True):
        if phone_ip not in {packet['src_ip'], packet['dst_ip']}:
            raise ValueError('PCAP 包含非目标设备的 IP 流量')
        yield dict(packet_index=packet['index'], ts_epoch=packet['ts_epoch'],
                   length=packet['length'], captured_length=packet['captured_length'],
                   direction='in' if packet['dst_ip']==phone_ip else 'out', ip_protocol=packet['ip_protocol'],
                   in_collection_interval=value['router_start_epoch'] <= packet['ts_epoch'] < value['router_end_epoch'])


def write_packet_csv(out, value):
    count = 0
    with (out/'packets.csv').open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=PACKET_FIELDS)
        writer.writeheader()
        for row in packet_rows(out/'capture.pcap', value):
            writer.writerow(row)
            count += 1
    return count


def export_rows(value):
    rows = []
    for index,row in enumerate(value['timeline'],1):
        rows.append(dict(segment_id=f'interval-{index:04d}', label=row['label'], app=row['app'],
                         pc_start_utc=datetime.fromtimestamp(row['pc_start_epoch'],timezone.utc).isoformat(),
                         pc_end_utc=datetime.fromtimestamp(row['pc_end_epoch'],timezone.utc).isoformat(),
                         pc_start_epoch=row['pc_start_epoch'],pc_end_epoch=row['pc_end_epoch'],
                         router_start_epoch=row['router_start_epoch'],router_end_epoch=row['router_end_epoch'],
                         duration_seconds=row['pc_end_epoch']-row['pc_start_epoch'],
                         label_status=row['review_status'],
                         usable_label=row['review_status'] in {'recorded','confirmed'} and row['label']!='unknown',
                         clock_uncertainty_seconds=value['clock_uncertainty_seconds'],
                         reason=row['reason'],source=row['source']))
        if value['schema'] == 'manual-ground-truth-timeline-v2':
            rows[-1]['input_eligible'] = rows[-1]['usable_label']
    return rows


def verify_export(out):
    out = Path(out).resolve()
    manifest = read_json(out/'export_manifest.json')
    if manifest['status'] != 'complete':
        raise ValueError('导出未完成')
    for name,expected in manifest['artifact_sha256'].items():
        path = (out/name.replace('\\','/')).resolve()
        if not path.is_relative_to(out) or sha256(path)!=expected:
            raise ValueError('导出文件校验失败：'+name)
    for name,expected in manifest['original_source_sha256'].items():
        path = out/'capture.pcap' if name=='capture.pcap' else out/'evidence'/name
        if sha256(path) != expected:
            raise ValueError('导出副本与原始文件指纹不一致：'+name)
    value = read_json(out/'ground_truth.json')
    if "manual_protocol" in value:
        source_manifest = read_json(out/'evidence'/'collection_manifest.json')
        points = event_windows(read_events(out/'evidence'), source_manifest)
        clock, end_clock = source_manifest['clock_start'], source_manifest['clock_end']
        uncertainty = max(clock['uncertainty_seconds'],
                          abs(end_clock['offset_seconds']-clock['offset_seconds'])+end_clock['uncertainty_seconds'])
        for point in points:
            point['clock_uncertainty_seconds'] = uncertainty
        if (value['manual_protocol'] != source_manifest['manual_protocol'] or
                value['event_windows'] != points or read_json(out/'event_windows.json') != points):
            raise ValueError('导出事件窗口与原始打点不一致')
        if points:
            with (out/'event_windows.csv').open(encoding='utf-8-sig', newline='') as handle:
                if list(csv.DictReader(handle)) != [{k:str(v) for k,v in p.items()} for p in points]:
                    raise ValueError('事件 CSV 与原始打点不一致')
    validate_timeline(value['timeline'],value['pc_start_epoch'],value['pc_end_epoch'])
    expected = export_rows(value)
    for filename,rows in [('ground_truth.csv',expected),('labeled_segments.csv',[r for r in expected if r['usable_label']])]:
        with (out/filename).open(encoding='utf-8-sig',newline='') as handle:
            actual = list(csv.DictReader(handle))
        if actual != [{key:str(v) for key,v in row.items()} for row in rows]:
            raise ValueError('导出标签与保存的时间线不一致')
    with (out/'packets.csv').open(encoding='utf-8',newline='') as handle:
        if sum(1 for _ in csv.DictReader(handle)) != manifest['ip_packets']:
            raise ValueError('导出包数量不一致')
    if manifest['schema']=='manual-ground-truth-export-v2':
        verify_packet_csv(out, value)
    return dict(valid=True, capture_ready=manifest['capture_ready'], fully_labeled_ready=manifest['fully_labeled_ready'],
                task_data_ready=manifest.get('task_data_ready'),
                ip_packets=manifest['ip_packets'], label_segments=manifest['label_segments'])


def verify_packet_csv(out, value):
    """Replay the copied PCAP, including gaps, and compare every exported packet field."""
    with (out/'packets.csv').open(encoding='utf-8', newline='') as handle:
        actual = iter(csv.DictReader(handle))
        for row in packet_rows(out/'capture.pcap', value):
            if next(actual, None) != {key: str(item) for key, item in row.items()}:
                raise ValueError('包 CSV 与连续 PCAP 不一致')
        if next(actual, None) is not None:
            raise ValueError('包 CSV 包含原始抓包之外的数据')
