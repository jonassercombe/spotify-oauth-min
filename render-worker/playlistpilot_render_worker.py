#!/usr/bin/env python3
"""Single-concurrency FFmpeg worker for PlaylistPilot creative renders."""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


API_BASE = os.environ.get("PLAYLISTPILOT_API_BASE", "https://playlist-pilot.com/api/meta/render-worker").rstrip("/")
WORKER_SECRET = os.environ.get("RENDER_WORKER_SECRET", "")
WORKER_ID = os.environ.get("RENDER_WORKER_ID", f"ffmpeg:{socket.gethostname()}")
POLL_SECONDS = max(2, int(os.environ.get("RENDER_POLL_SECONDS", "5")))
MAX_LOAD = max(0.5, float(os.environ.get("RENDER_MAX_LOAD", "3.6")))
HTTP_TIMEOUT = max(30, int(os.environ.get("RENDER_HTTP_TIMEOUT", "180")))
FONT_FILE = os.environ.get("RENDER_FONT_FILE", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("playlistpilot-render-worker")


def api(endpoint: str, payload: dict) -> dict:
    request = urllib.request.Request(
        f"{API_BASE}/{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-render-worker-secret": WORKER_SECRET},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def download(url: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "PlaylistPilotRenderWorker/1.0"})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response, target.open("wb") as output:
        while chunk := response.read(1024 * 256):
            output.write(chunk)


def upload(url: str, source: Path) -> None:
    request = urllib.request.Request(
        url,
        data=source.read_bytes(),
        headers={"Content-Type": "video/mp4", "cache-control": "max-age=3600", "x-upsert": "true"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"upload_http_{response.status}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:900]
        raise RuntimeError(f"upload_http_{error.code}: {detail}") from error


def dimensions(fmt: str) -> tuple[int, int]:
    return {"4:5": (720, 900), "1:1": (720, 720)}.get(fmt, (720, 1280))


def text_units(value: str) -> float:
    """Approximate DejaVu Sans Bold glyph widths in font-size units."""
    units = 0.0
    for character in value:
        if character.isspace():
            units += 0.32
        elif character in "ilI1.,:;!'|`":
            units += 0.30
        elif character in "MW@#%&mw":
            units += 0.88
        elif character.isupper():
            units += 0.70
        elif character.isdigit():
            units += 0.60
        else:
            units += 0.57
    return units


def wrap_visual(value: str, max_units: float) -> list[str]:
    """Wrap on visual width and split a single oversized token without truncating it."""
    lines: list[str] = []
    for paragraph in value.replace("\r", "").split("\n"):
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if current and text_units(candidate) > max_units:
                lines.append(current)
                current = ""
            while text_units(word) > max_units:
                split_at = max(1, len(word) - 1)
                while split_at > 1 and text_units(word[:split_at]) > max_units:
                    split_at -= 1
                lines.append(word[:split_at])
                word = word[split_at:]
            current = f"{current} {word}".strip()
        if current:
            lines.append(current)
    return lines or [""]


def fit_text(value: str, safe_width: int, safe_height: int, preferred_size: int, minimum_size: int) -> tuple[str, int, int]:
    """Fit all text inside a rectangular safe area by wrapping, then scaling down."""
    for font_size in range(preferred_size, minimum_size - 1, -2):
        line_spacing = max(4, int(font_size * 0.16))
        lines = wrap_visual(value, safe_width / font_size)
        rendered_height = len(lines) * font_size + max(0, len(lines) - 1) * line_spacing
        rendered_width = max(text_units(line) for line in lines) * font_size
        if rendered_width <= safe_width and rendered_height <= safe_height:
            return "\n".join(lines), font_size, line_spacing
    font_size = minimum_size
    line_spacing = max(3, int(font_size * 0.12))
    lines = wrap_visual(value, safe_width / font_size)
    return "\n".join(lines), font_size, line_spacing


def probe_duration(path: Path) -> float:
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return max(0.1, float(result.stdout.strip()))


def render(job: dict, workdir: Path) -> tuple[Path, float, int, int]:
    editor = job.get("editor") or {}
    width, height = dimensions(str(job.get("format") or editor.get("format") or "9:16"))
    template_id = str(editor.get("template_id") or "bold_center")
    template = {
        "bold_center": {"font_ratio": 0.078, "safe_x": 0.08, "safe_top": 0.18, "safe_bottom": 0.72, "vertical": "center", "cover_ratio": 0.42},
        "editorial_top": {"font_ratio": 0.064, "safe_x": 0.07, "safe_top": 0.10, "safe_bottom": 0.49, "vertical": "top", "cover_ratio": 0.34},
        "minimal_bottom": {"font_ratio": 0.052, "safe_x": 0.07, "safe_top": 0.58, "safe_bottom": 0.84, "vertical": "top", "cover_ratio": 0.30},
    }.get(template_id, {"font_ratio": 0.078, "safe_x": 0.08, "safe_top": 0.18, "safe_bottom": 0.72, "vertical": "center", "cover_ratio": 0.42})
    clip_start = max(0.0, float(editor.get("trim_start", editor.get("clip_start", 0)) or 0))
    clip_end = max(clip_start + 0.2, float(editor.get("trim_end", editor.get("clip_end", clip_start + 15)) or clip_start + 15))
    duration = min(30.0, clip_end - clip_start)
    hook_start = max(0.0, float(editor.get("hook_start") or 0))
    hook_end = min(duration, max(hook_start + 0.2, float(editor.get("hook_end") or 4)))
    hook_position = str(editor.get("hook_position") or "center")
    if template_id == "bold_center":
        position_zones = {"top": (0.10, 0.43, "top"), "center": (0.18, 0.72, "center"), "bottom": (0.57, 0.84, "top")}
        safe_top, safe_bottom, vertical = position_zones.get(hook_position, position_zones["center"])
    else:
        safe_top, safe_bottom, vertical = template["safe_top"], template["safe_bottom"], template["vertical"]
    safe_x = int(width * template["safe_x"])
    safe_width = width - (safe_x * 2)
    safe_top_px = int(height * safe_top)
    safe_height = int(height * (safe_bottom - safe_top))
    text_align = str(editor.get("text_align") or "center")
    hook_x = {"left": str(safe_x), "right": f"w-text_w-{safe_x}"}.get(text_align, "(w-text_w)/2")
    text_color = str(editor.get("text_color") or "#ffffff").replace("#", "0x")
    overlay = min(0.85, max(0.0, float(editor.get("overlay_opacity", editor.get("overlay_strength", 0.28)) or 0.0)))
    hook = str(editor.get("hook_text") or job.get("hook_text") or "").strip()
    cta = str(editor.get("cta_text") or "").strip()
    show_cta = bool(editor.get("show_cta", True)) and bool(cta)
    show_cover = bool(editor.get("show_cover", True)) and bool(job.get("playlist_cover_url"))

    source = workdir / "source.mp4"
    output = workdir / "render.mp4"
    hook_file = workdir / "hook.txt"
    cta_file = workdir / "cta.txt"
    download(str(job["video_url"]), source)
    fitted_hook, hook_font_size, hook_line_spacing = fit_text(
        hook, safe_width, safe_height, max(34, int(width * template["font_ratio"])), max(24, int(width * 0.038))
    )
    fitted_cta, cta_font_size, cta_line_spacing = fit_text(
        cta, int(width * 0.84), int(height * 0.11), max(24, int(width * 0.043)), max(18, int(width * 0.027))
    )
    hook_y = str(safe_top_px) if vertical == "top" else f"{safe_top_px}+({safe_height}-text_h)/2"
    hook_file.write_text(fitted_hook, encoding="utf-8")
    cta_file.write_text(fitted_cta, encoding="utf-8")

    command = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-ss", f"{clip_start:.3f}", "-i", str(source)]
    cover = workdir / "cover.jpg"
    if show_cover:
        download(str(job["playlist_cover_url"]), cover)
        command.extend(["-loop", "1", "-i", str(cover)])

    filters = [f"[0:v]scale={width}:{height}:force_original_aspect_ratio=increase,crop={width}:{height},drawbox=x=0:y=0:w=iw:h=ih:color=black@{overlay:.3f}:t=fill[base]"]
    current = "base"
    if show_cover:
        cover_size = max(160, int(width * template["cover_ratio"]))
        filters.append(f"[1:v]scale={cover_size}:{cover_size}:force_original_aspect_ratio=decrease[cover]")
        filters.append(f"[{current}][cover]overlay=(W-w)/2:H-h-{max(100, int(height * 0.10))}:enable='between(t,4,{duration:.3f})'[covered]")
        current = "covered"

    text_filters = []
    if hook:
        text_filters.append(
            "drawtext="
            f"fontfile='{FONT_FILE}':textfile='{hook_file}':fontcolor={text_color}:fontsize={hook_font_size}:"
            f"line_spacing={hook_line_spacing}:x={hook_x}:y={hook_y}:fix_bounds=1:shadowcolor=black@0.82:shadowx=3:shadowy=3:"
            f"enable='between(t,{hook_start:.3f},{hook_end:.3f})'"
        )
    if show_cta:
        text_filters.append(
            "drawtext="
            f"fontfile='{FONT_FILE}':textfile='{cta_file}':fontcolor=white:fontsize={cta_font_size}:line_spacing={cta_line_spacing}:"
            f"x=(w-text_w)/2:y=h-text_h-{max(38, int(height * 0.035))}:fix_bounds=1:shadowcolor=black@0.75:shadowx=2:shadowy=2:"
            f"enable='between(t,{max(0.0, duration - 4):.3f},{duration:.3f})'"
        )
    tail = ",".join(text_filters + ["format=yuv420p"])
    filters.append(f"[{current}]{tail}[out]")
    command.extend([
        "-filter_complex", ";".join(filters), "-map", "[out]", "-an", "-t", f"{duration:.3f}",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-movflags", "+faststart", "-threads", "2", str(output),
    ])
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=600)
    return output, min(duration, probe_duration(output)), width, height


def process_one() -> bool:
    claimed = api("claim", {"worker_id": WORKER_ID})
    job = claimed.get("job")
    if not job:
        return False
    LOG.info("claimed job %s", job["id"])
    try:
        with tempfile.TemporaryDirectory(prefix="playlistpilot-render-") as tmp:
            output, duration, width, height = render(job, Path(tmp))
            upload(str(job["upload_url"]), output)
            api("complete", {"job_id": job["id"], "worker_id": WORKER_ID, "duration_seconds": duration, "width": width, "height": height, "bytes": output.stat().st_size})
        LOG.info("completed job %s", job["id"])
    except Exception as error:
        message = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            message = (error.stderr or message)[-900:]
        LOG.exception("job %s failed", job["id"])
        try:
            api("fail", {"job_id": job["id"], "worker_id": WORKER_ID, "error_code": "ffmpeg_render_failed", "error_message": message[:900], "retryable": False})
        except Exception:
            LOG.exception("could not report failed job %s", job["id"])
    return True


def main() -> None:
    if not WORKER_SECRET:
        raise SystemExit("RENDER_WORKER_SECRET is required")
    LOG.info("worker %s started", WORKER_ID)
    while True:
        try:
            if os.getloadavg()[0] <= MAX_LOAD:
                if process_one():
                    continue
            else:
                LOG.info("host load %.2f above %.2f; waiting", os.getloadavg()[0], MAX_LOAD)
        except urllib.error.HTTPError as error:
            LOG.error("worker API returned %s: %s", error.code, error.read().decode("utf-8", "replace")[:500])
        except Exception:
            LOG.exception("worker loop error")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
