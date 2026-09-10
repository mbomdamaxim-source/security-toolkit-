"""CSV export for Traffic Dashboard snapshots."""
from __future__ import annotations

import csv
from pathlib import Path

from modules.traffic.logic import TrafficSnapshot, analyze_connections, top_talkers


def export_snapshot_csv(destination, snapshot: TrafficSnapshot) -> Path:
    """Write the current snapshot (connections + findings summary) to CSV."""
    path = Path(destination)
    if path.suffix.lower() != ".csv":
        raise ValueError("Choose a .csv report file.")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Bastion traffic snapshot", snapshot.taken_at])
        writer.writerow([])
        writer.writerow(["Connections"])
        writer.writerow(["Process", "Local address", "Local port",
                         "Remote address", "Remote port", "Path"])
        for connection in snapshot.connections:
            writer.writerow([
                connection.process_name or str(connection.process_id),
                connection.local_address,
                connection.local_port,
                connection.remote_address,
                connection.remote_port,
                connection.process_path,
            ])
        writer.writerow([])
        writer.writerow(["Findings"])
        writer.writerow(["Severity", "Title", "Detail"])
        for finding in analyze_connections(snapshot.connections):
            writer.writerow([finding.severity, finding.title, finding.detail])
        writer.writerow([])
        writer.writerow(["Top talkers"])
        writer.writerow(["Process", "Connections", "Distinct remotes"])
        for talker in top_talkers(snapshot.connections):
            writer.writerow([talker.process, talker.connections, talker.distinct_remotes])
    return path
