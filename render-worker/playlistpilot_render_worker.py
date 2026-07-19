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
import base64
from pathlib import Path


API_BASE = os.environ.get("PLAYLISTPILOT_API_BASE", "https://playlist-pilot.com/api/meta/render-worker").rstrip("/")
WORKER_SECRET = os.environ.get("RENDER_WORKER_SECRET", "")
WORKER_ID = os.environ.get("RENDER_WORKER_ID", f"ffmpeg:{socket.gethostname()}")
POLL_SECONDS = max(2, int(os.environ.get("RENDER_POLL_SECONDS", "5")))
MAX_LOAD = max(0.5, float(os.environ.get("RENDER_MAX_LOAD", "3.6")))
HTTP_TIMEOUT = max(30, int(os.environ.get("RENDER_HTTP_TIMEOUT", "180")))
FONT_FILE = os.environ.get("RENDER_FONT_FILE", "/usr/share/fonts/truetype/lato/Lato-Black.ttf")
FONT_REGULAR_FILE = os.environ.get("RENDER_FONT_REGULAR_FILE", "/usr/share/fonts/truetype/lato/Lato-Regular.ttf")

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


def wrap_visual(value: str, max_units: float, split_oversized: bool = True) -> list[str]:
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
            while split_oversized and text_units(word) > max_units:
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
    width_safety = 1.10
    for font_size in range(preferred_size, minimum_size - 1, -2):
        line_spacing = max(3, int(font_size * 0.10))
        lines = wrap_visual(value, safe_width / (font_size * width_safety), split_oversized=False)
        rendered_height = len(lines) * font_size + max(0, len(lines) - 1) * line_spacing
        rendered_width = max(text_units(line) for line in lines) * font_size * width_safety
        if rendered_width <= safe_width and rendered_height <= safe_height:
            return "\n".join(lines), font_size, line_spacing
    font_size = minimum_size
    line_spacing = max(3, int(font_size * 0.09))
    lines = wrap_visual(value, safe_width / (font_size * width_safety))
    return "\n".join(lines), font_size, line_spacing


def fade_alpha(start: float, end: float, fade: float = 0.38) -> str:
    """FFmpeg expression for a soft fade at both ends of an element's lifetime."""
    fade = min(fade, max(0.08, (end - start) / 3))
    return (
        f"if(lt(t\\,{start + fade:.3f})\\,(t-{start:.3f})/{fade:.3f}\\,"
        f"if(gt(t\\,{end - fade:.3f})\\,({end:.3f}-t)/{fade:.3f}\\,1))"
    )


def probe_duration(path: Path) -> float:
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return max(0.1, float(result.stdout.strip()))


def extract_qa_frames(video: Path, duration: float, workdir: Path) -> list[dict]:
    """Return three bounded JPEGs spanning the finished composition for post-render Vision QA."""
    frames: list[dict] = []
    timestamps = [min(duration * ratio, max(0.0, duration - 0.08)) for ratio in (0.08, 0.38, 0.82)]
    for index, timestamp in enumerate(timestamps):
        target = workdir / f"qa-{index}.jpg"
        subprocess.run(
            [
                "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                "-ss", f"{timestamp:.3f}", "-i", str(video), "-frames:v", "1",
                "-vf", "scale=360:-2", "-q:v", "8", str(target),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=45,
        )
        encoded = base64.b64encode(target.read_bytes()).decode("ascii")
        frames.append({"timestamp_seconds": round(timestamp, 3), "mime_type": "image/jpeg", "base64": encoded})
    return frames


def render(job: dict, workdir: Path) -> tuple[Path, float, int, int]:
    editor = job.get("editor") or {}
    width, height = dimensions(str(job.get("format") or editor.get("format") or "9:16"))
    template_id = str(editor.get("template_id") or "bold_center")
    template = {
        "bold_center": {"font_ratio": 0.098, "safe_x": 0.13, "safe_top": 0.22, "safe_bottom": 0.54, "vertical": "center", "cover_ratio": 0.50},
        "editorial_top": {"font_ratio": 0.084, "safe_x": 0.13, "safe_top": 0.19, "safe_bottom": 0.46, "vertical": "top", "cover_ratio": 0.38},
        "minimal_bottom": {"font_ratio": 0.074, "safe_x": 0.13, "safe_top": 0.55, "safe_bottom": 0.73, "vertical": "center", "cover_ratio": 0.34},
    }.get(template_id, {"font_ratio": 0.098, "safe_x": 0.13, "safe_top": 0.22, "safe_bottom": 0.54, "vertical": "center", "cover_ratio": 0.50})
    clip_start = max(0.0, float(editor.get("trim_start", editor.get("clip_start", 0)) or 0))
    clip_end = max(clip_start + 0.2, float(editor.get("trim_end", editor.get("clip_end", clip_start + 15)) or clip_start + 15))
    duration = min(30.0, max(10.0, clip_end - clip_start))
    hook_start = max(0.0, float(editor.get("hook_start") or 0))
    hook_end = min(duration, max(hook_start + 0.2, float(editor.get("hook_end") or 4)))
    hook_position = str(editor.get("hook_position") or "center")
    if template_id == "bold_center":
        position_zones = {"top": (0.19, 0.45, "top"), "center": (0.22, 0.54, "center"), "bottom": (0.53, 0.72, "center")}
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
    playlist_name = str(job.get("playlist_name") or "").strip()
    show_cta = bool(editor.get("show_cta", True)) and bool(cta)
    show_cover = bool(editor.get("show_cover", True)) and bool(job.get("playlist_cover_url"))

    source = workdir / "source.mp4"
    output = workdir / "render.mp4"
    hook_file = workdir / "hook.txt"
    cta_file = workdir / "cta.txt"
    playlist_file = workdir / "playlist.txt"
    download(str(job["video_url"]), source)
    audio_url = str(job.get("audio_url") or "").strip()
    audio = workdir / "audio"
    song_start = max(0.0, float(job.get("song_start_seconds") or 0))
    song_end = max(song_start, float(job.get("song_end_seconds") or 0))
    audio_duration = min(duration, song_end - song_start) if song_end > song_start else duration
    fade_in = min(max(0.0, float(job.get("fade_in_seconds") or 0)), max(0.0, audio_duration / 2 - 0.01))
    fade_out = min(max(0.0, float(job.get("fade_out_seconds") or 0)), max(0.0, audio_duration / 2 - 0.01))
    audio_gain_db = min(12.0, max(-24.0, float(job.get("audio_gain_db") or 0)))
    if audio_url:
        download(audio_url, audio)
    hook_fit_width = safe_width - (max(22, int(width * 0.04)) if template_id == "editorial_top" else 0)
    fitted_hook, hook_font_size, hook_line_spacing = fit_text(
        hook, hook_fit_width, safe_height, max(42, int(width * template["font_ratio"])), max(30, int(width * 0.046))
    )
    fitted_cta, cta_font_size, cta_line_spacing = fit_text(
        cta.upper(), int(width * 0.70), int(height * 0.07), max(22, int(width * 0.036)), max(18, int(width * 0.028))
    )
    playlist_width = int(width * (0.74 if template_id == "bold_center" else 0.44))
    fitted_playlist, playlist_font_size, playlist_line_spacing = fit_text(
        playlist_name, playlist_width, int(height * 0.11), max(30, int(width * 0.052)), max(22, int(width * 0.034))
    )
    hook_y = str(safe_top_px) if vertical == "top" else f"{safe_top_px}+({safe_height}-text_h)/2"
    hook_file.write_text(fitted_hook, encoding="utf-8")
    cta_file.write_text(fitted_cta, encoding="utf-8")
    playlist_file.write_text(fitted_playlist, encoding="utf-8")

    command = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-stream_loop", "-1", "-ss", f"{clip_start:.3f}", "-i", str(source)]
    cover = workdir / "cover.jpg"
    if show_cover:
        download(str(job["playlist_cover_url"]), cover)
        command.extend(["-loop", "1", "-i", str(cover)])
    audio_input_index = 2 if show_cover else 1
    if audio_url:
        command.extend(["-ss", f"{song_start:.3f}", "-i", str(audio)])

    filters = [f"[0:v]scale={width}:{height}:force_original_aspect_ratio=increase,crop={width}:{height},drawbox=x=0:y=0:w=iw:h=ih:color=black@{overlay:.3f}:t=fill[base]"]
    current = "base"
    accent_color = "white"
    reveal_start = min(duration, 4.0)
    safe_bottom_ratio = 0.75 if height / width > 1.5 else 0.84
    cta_bottom = int(height * (1.0 - safe_bottom_ratio))
    cover_size = max(150, int(width * template["cover_ratio"]))
    if template_id == "bold_center":
        cover_x = int((width - cover_size) / 2)
        cover_y = int(height * 0.31)
        playlist_x = "(w-text_w)/2"
        playlist_y = cover_y + cover_size + max(20, int(height * 0.022))
    else:
        cover_x = safe_x
        cover_y = int(height * (0.28 if template_id == "editorial_top" else 0.18))
        playlist_x = str(cover_x + cover_size + max(22, int(width * 0.035)))
        playlist_y = cover_y + max(4, int(height * 0.008))
    if show_cover:
        cover_fade_out = max(reveal_start + 0.5, duration - 0.45)
        filters.append(
            f"[1:v]scale={cover_size}:{cover_size}:force_original_aspect_ratio=increase,crop={cover_size}:{cover_size},format=rgba,"
            f"fade=t=in:st={reveal_start:.3f}:d=0.45:alpha=1,fade=t=out:st={cover_fade_out:.3f}:d=0.45:alpha=1[cover]"
        )
        filters.append(f"[{current}][cover]overlay={cover_x}:{cover_y}:enable='between(t,{reveal_start:.3f},{duration:.3f})'[covered]")
        current = "covered"

    text_filters = []
    if hook:
        hook_alpha = fade_alpha(hook_start, hook_end)
        if template_id == "editorial_top":
            label_font_size = max(18, int(width * 0.030))
            label_y = max(int(height * 0.11), safe_top_px - max(30, int(height * 0.038)))
            text_filters.append(
                "drawtext="
                f"fontfile='{FONT_REGULAR_FILE}':text='CURATED PLAYLIST':fontcolor=white:fontsize={label_font_size}:"
                f"x={safe_x}:y={label_y}:alpha='{hook_alpha}':fix_bounds=1:shadowcolor=black@0.5:shadowx=1:shadowy=2:"
                f"enable='between(t,{hook_start:.3f},{hook_end:.3f})'"
            )
        if template_id == "editorial_top":
            hook_x = str(safe_x + max(22, int(width * 0.04)))
        text_filters.append(
            "drawtext="
            f"fontfile='{FONT_FILE}':textfile='{hook_file}':fontcolor={text_color}:fontsize={hook_font_size}:"
            f"line_spacing={hook_line_spacing}:x={hook_x}:y={hook_y}:alpha='{hook_alpha}':fix_bounds=1:shadowcolor=black@0.55:shadowx=2:shadowy=3:"
            f"enable='between(t,{hook_start:.3f},{hook_end:.3f})'"
        )
    if show_cover and playlist_name:
        reveal_alpha = fade_alpha(reveal_start, duration, 0.45)
        text_filters.append(
            "drawtext="
            f"fontfile='{FONT_FILE}':textfile='{playlist_file}':fontcolor=white:fontsize={playlist_font_size}:line_spacing={playlist_line_spacing}:"
            f"x={playlist_x}:y={playlist_y}:alpha='{reveal_alpha}':fix_bounds=1:shadowcolor=black@0.65:shadowx=2:shadowy=2:"
            f"enable='between(t,{reveal_start:.3f},{duration:.3f})'"
        )
    if show_cta:
        cta_start = max(0.0, duration - 4)
        cta_alpha = fade_alpha(cta_start, duration, 0.45)
        text_filters.append(
            "drawtext="
            f"fontfile='{FONT_REGULAR_FILE}':textfile='{cta_file}':fontcolor=white:fontsize={cta_font_size}:line_spacing={cta_line_spacing}:"
            f"x=(w-text_w)/2:y=h-text_h-{cta_bottom}:alpha='{cta_alpha}':fix_bounds=1:shadowcolor=black@0.65:shadowx=2:shadowy=2:"
            f"enable='between(t,{cta_start:.3f},{duration:.3f})'"
        )
    tail = ",".join(text_filters + ["format=yuv420p"])
    filters.append(f"[{current}]{tail}[out]")
    if audio_url:
        audio_filters = [f"atrim=duration={audio_duration:.3f}", "asetpts=PTS-STARTPTS"]
        if abs(audio_gain_db) > 0.01:
            audio_filters.append(f"volume={audio_gain_db:.2f}dB")
        if fade_in > 0:
            audio_filters.append(f"afade=t=in:st=0:d={fade_in:.3f}")
        if fade_out > 0:
            audio_filters.append(f"afade=t=out:st={max(0.0, audio_duration - fade_out):.3f}:d={fade_out:.3f}")
        filters.append(f"[{audio_input_index}:a:0]{','.join(audio_filters)}[audioout]")
    command.extend(["-filter_complex", ";".join(filters), "-map", "[out]"])
    if audio_url:
        command.extend(["-map", "[audioout]", "-c:a", "aac", "-b:a", "192k"])
    else:
        command.append("-an")
    command.extend([
        "-t", f"{duration:.3f}", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
        "-movflags", "+faststart", "-threads", "2", str(output),
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
            qa_frames = extract_qa_frames(output, duration, Path(tmp))
            api("complete", {"job_id": job["id"], "worker_id": WORKER_ID, "duration_seconds": duration, "width": width, "height": height, "bytes": output.stat().st_size, "qa_frames": qa_frames})
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
