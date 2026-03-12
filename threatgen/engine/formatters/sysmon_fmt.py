from __future__ import annotations

from datetime import datetime

from .base import BaseFormatter

SYSMON_GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"


class SysmonFormatter(BaseFormatter):
    def format(self, ts: datetime, **fields) -> str:
        event_id = fields.get("event_id", 1)
        computer = fields.get("computer", "UNKNOWN")
        task = fields.get("task", event_id)
        data_fields: list[tuple[str, str]] = fields.get("data_fields", [])

        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        data_xml = "\n    ".join(
            f'<Data Name="{name}">{value}</Data>' for name, value in data_fields
        )

        return (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
            f"  <System>\n"
            f'    <Provider Name="Microsoft-Windows-Sysmon" Guid="{SYSMON_GUID}" />\n'
            f"    <EventID>{event_id}</EventID>\n"
            f"    <Version>5</Version>\n"
            f"    <Level>4</Level>\n"
            f"    <Task>{task}</Task>\n"
            f"    <Opcode>0</Opcode>\n"
            f'    <TimeCreated SystemTime="{ts_str}" />\n'
            f"    <Computer>{computer}</Computer>\n"
            f"  </System>\n"
            f"  <EventData>\n"
            f"    {data_xml}\n"
            f"  </EventData>\n"
            f"</Event>"
        )
