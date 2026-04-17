from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phantom.models import ReportBundle


class ReportWriter:
    def __init__(self, base_dir: Path, run_id: str) -> None:
        self.base_dir = base_dir
        self.run_id = run_id
        self.report_dir = self.base_dir / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        template_dir = self.base_dir / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def write(self, bundle: ReportBundle) -> dict[str, str]:
        json_path = self.report_dir / f"{self.run_id}.json"
        html_path = self.report_dir / f"{self.run_id}.html"
        files = {
            "json": str(json_path),
            "html": str(html_path),
            "log": str(self.base_dir / "logs" / f"{self.run_id}.log"),
        }
        payload = asdict(bundle)
        payload["files"] = files

        with json_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

        template = self.env.get_template("report.html")
        html = template.render(report=payload)
        with html_path.open("w", encoding="utf-8") as handle:
            handle.write(html)

        return files

