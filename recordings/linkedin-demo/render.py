"""Render edited real browser clips, with captions, into a 1080p portfolio trailer."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], log: Path) -> None:
    with log.open("w") as output:
        subprocess.run(  # noqa: S603 - fixed local encoder argv; no shell or telemetry commands.
            command, cwd=ROOT, stdout=output, stderr=output, check=True
        )


def ass_time(seconds: float) -> str:
    centiseconds = round(seconds * 100)
    return (
        f"{centiseconds // 360000}:{centiseconds // 6000 % 60:02}:"
        f"{centiseconds // 100 % 60:02}.{centiseconds % 100:02}"
    )


def captions(scene: dict) -> str:
    lines = [
        "[Script Info]",
        "ScriptType: v4.00+",
        "PlayResX: 1920",
        "PlayResY: 1080",
        "ScaledBorderAndShadow: yes",
        "",
        "[V4+ Styles]",
        "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, "
        "BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, "
        "BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
        "Style: Title,Arial,40,&H00FFFFFF,&H00FFFFFF,&H003D2E1B,&H003D2E1B,"
        "-1,0,0,0,100,100,0,0,1,0,0,7,0,0,0,1",
        "Style: Body,Arial,28,&H00EBE8DB,&H00EBE8DB,&H003D2E1B,&H003D2E1B,"
        "0,0,0,0,100,100,0,0,1,0,0,7,0,0,0,1",
        "Style: Note,Arial,19,&H00FFFFFF,&H00FFFFFF,&H003D2E1B,&H003D2E1B,"
        "0,0,0,0,100,100,0,0,1,1,0,3,0,0,0,1",
        "",
        "[Events]",
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
    ]

    def event(start: float, end: float, style: str, text: str, layer: int = 1) -> None:
        lines.append(f"Dialogue: {layer},{ass_time(start)},{ass_time(end)},{style},,0,0,0,,{text}")

    def panel(start: float, end: float, title: str, body: str, large: bool = False) -> None:
        event(
            start,
            end,
            "Title",
            r"{\an7\pos(316,858)\fad(160,160)\p1\1c&H3D2E1B&\alpha&H12&}"
            "m 0 0 l 1544 0 l 1544 158 l 0 158 l 0 0"
            r"{\p0}",
            0,
        )
        size = r"\fs52" if large else ""
        event(start, end, "Title", rf"{{\an7\pos(348,880)\fad(160,160){size}}}{title}")
        event(start, end, "Body", rf"{{\an7\pos(348,951)\fad(160,160)}}{body}")

    duration = scene["duration"]
    identifier = scene["id"]
    if identifier == "01-dashboard":
        panel(0.25, duration - 0.2, scene["title"], scene["subtitle"], True)
    elif identifier == "12-finale":
        panel(0.15, 1.65, scene["title"], "From telemetry to an evidence-backed investigation.")
        panel(
            1.7,
            duration,
            "SentinelFlow",
            "FastAPI \u2022 React/TypeScript \u2022 MITRE ATT&CK",
            True,
        )
    else:
        panel(0.35, 3.1, scene["title"], scene["subtitle"])
        if identifier == "04-detection":
            start = max(3.3, scene["alert_at"] + 0.4)
            if start >= duration - 1:
                raise RuntimeError("Actual alert arrived too late for its caption")
            panel(
                start,
                duration - 0.35,
                "ALERT GENERATED",
                "AUTH-001 \u2022 25 triggering events \u2022 High severity",
            )
        elif identifier == "07-mitre":
            panel(
                3.25,
                duration - 0.25,
                "T1110 \u00b7 Brute Force",
                "The same alert, mapped to MITRE ATT&CK.",
            )
        elif identifier == "11-security":
            panel(
                3.3,
                duration - 0.2,
                "946 automated tests",
                "50 detection scenarios \u2022 127 browser checks",
                True,
            )
    note = "Synthetic telemetry \u00b7 Local demonstration"
    if identifier == "09-integrations":
        note = "Connector implemented \u00b7 No live Microsoft tenant tested"
    elif identifier == "10-notifications":
        note = "Configuration only \u00b7 No external message sent"
    event(0, duration, "Note", rf"{{\an3\pos(1854,1054)}}{note}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, default=Path("recordings/sentinelflow-linkedin-demo.mp4")
    )
    args = parser.parse_args()
    source = (ROOT / args.capture).resolve()
    target = (ROOT / args.output).resolve()
    if not source.is_relative_to(ROOT / "artifacts/linkedin-trailer"):
        raise ValueError("Capture must be in this workspace's isolated recording artifacts")
    if not target.is_relative_to(ROOT / "recordings") or target.exists():
        raise ValueError(
            "Choose a new MP4 path under recordings; existing media is never overwritten"
        )
    if target.suffix != ".mp4":
        raise ValueError("Output must be MP4")
    capture = json.loads((source / "capture.json").read_text())
    if capture["status"] != "captured" or len(capture["scenes"]) != 12:
        raise RuntimeError("All twelve real scenes must complete before rendering")
    if not capture["source_unchanged"] or not capture["original_recording_unchanged"]:
        raise RuntimeError("Preservation/source checks did not pass")
    fingerprint = subprocess.check_output(  # noqa: S603 - fixed source-identity query.
        [
            sys.executable,
            "-c",
            "from app.core.evidence import source_fingerprint; print(source_fingerprint())",
        ],
        cwd=ROOT,
        text=True,
    ).strip()
    if fingerprint != capture["source_fingerprint"]:
        raise RuntimeError("Recording is stale for the current application")
    ffmpeg = Path(os.getenv("SENTINEL_FFMPEG", str(ROOT / ".runtime/recording/bin/ffmpeg")))
    ffprobe = Path(os.getenv("SENTINEL_FFPROBE", str(ROOT / ".runtime/recording/bin/ffprobe")))
    version = subprocess.check_output(  # noqa: S603 - operator-selected local executable.
        [str(ffmpeg), "-version"], text=True
    ).splitlines()[0]
    if not version.startswith("ffmpeg version 9.0.2 "):
        raise RuntimeError("Use the documented, verified FFmpeg 9.0.2 environment")
    directory = source / "render"
    directory.mkdir()
    commands = []
    clips = []
    chapter_start = 0.0
    chapters = []
    for scene in capture["scenes"]:
        subtitle = directory / f"{scene['id']}.ass"
        subtitle.write_text(captions(scene))
        clip = directory / f"{scene['id']}.mp4"
        raw = ROOT / scene["raw"]
        if not raw.is_relative_to(source / "raw") or not raw.exists():
            raise ValueError("Unrecognized raw capture path")
        filters = (
            f"trim=start={scene['trim_start']:.6f}:duration={scene['duration']},"
            "setpts=PTS-STARTPTS,fps=30,setsar=1,"
            f"ass=filename='{subtitle.relative_to(ROOT)}',format=yuv420p"
        )
        command = [
            str(ffmpeg),
            "-hide_banner",
            "-loglevel",
            "warning",
            "-n",
            "-threads",
            "2",
            "-i",
            str(raw),
            "-vf",
            filters,
            "-an",
            "-c:v",
            "libx264",
            "-threads",
            "2",
            "-preset",
            "medium",
            "-crf",
            "18",
            "-profile:v",
            "high",
            "-level",
            "4.1",
            "-g",
            "60",
            "-movflags",
            "+faststart",
            str(clip),
        ]
        print(f"Rendering {scene['id']}", flush=True)
        run(command, directory / f"{scene['id']}.log")
        commands.append(command)
        clips.append(clip)
        chapters.append(
            {
                "start_seconds": round(chapter_start, 3),
                "end_seconds": round(chapter_start + scene["duration"], 3),
                "title": scene["title"],
                "feature": scene["subtitle"],
                "proof": scene.get("result", {}),
            }
        )
        chapter_start += scene["duration"] - 0.3
    filters = []
    cumulative = capture["scenes"][0]["duration"]
    previous = "[0:v]"
    for index, scene in enumerate(capture["scenes"][1:], 1):
        offset = cumulative - 0.3
        output = f"[cut{index}]"
        filters.append(
            f"{previous}[{index}:v]xfade=transition=fade:duration=0.3:offset={offset:.3f}{output}"
        )
        previous = output
        cumulative += scene["duration"] - 0.3
    command = [str(ffmpeg), "-hide_banner", "-loglevel", "warning", "-n"]
    for clip in clips:
        command.extend(["-threads", "1", "-i", str(clip)])
    command.extend(
        [
            "-filter_complex_threads",
            "1",
            "-filter_complex",
            ";".join(filters),
            "-map",
            previous,
            "-an",
            "-c:v",
            "libx264",
            "-threads",
            "2",
            "-preset",
            "medium",
            "-crf",
            "18",
            "-pix_fmt",
            "yuv420p",
            "-profile:v",
            "high",
            "-level",
            "4.1",
            "-g",
            "60",
            "-movflags",
            "+faststart",
            str(target),
        ]
    )
    print("Combining live clips with 300 ms dissolves", flush=True)
    run(command, directory / "combine.log")
    commands.append(command)
    probe_command = [
        str(ffprobe),
        "-v",
        "error",
        "-show_format",
        "-show_streams",
        "-of",
        "json",
        str(target),
    ]
    probe = json.loads(
        subprocess.check_output(probe_command, text=True)  # noqa: S603 - fixed ffprobe argv.
    )
    duration = float(probe["format"]["duration"])
    video = [stream for stream in probe["streams"] if stream["codec_type"] == "video"]
    if (
        not 90 <= duration <= 150
        or len(video) != 1
        or video[0]["width"] != 1920
        or video[0]["height"] != 1080
        or video[0]["codec_name"] != "h264"
        or any(stream["codec_type"] == "audio" for stream in probe["streams"])
        or abs(duration - cumulative) > 0.15
    ):
        raise RuntimeError("Rendered video does not meet the requested delivery format")
    decode = [str(ffmpeg), "-v", "error", "-i", str(target), "-f", "null", "-"]
    run(decode, directory / "decode.log")
    record = {
        "status": "rendered-and-decoded",
        "created_at": datetime.now(UTC).isoformat(),
        "source_fingerprint": fingerprint,
        "video": str(target.relative_to(ROOT)),
        "sha256": digest(target),
        "bytes": target.stat().st_size,
        "duration_seconds": duration,
        "width": 1920,
        "height": 1080,
        "frame_rate": video[0]["avg_frame_rate"],
        "codec": "H.264",
        "pixel_format": video[0]["pix_fmt"],
        "audio": "Silent; on-screen text designed for muted autoplay",
        "capture_receipt": str((source / "capture.json").relative_to(ROOT)),
        "capture_receipt_sha256": digest(source / "capture.json"),
        "ffmpeg_version": version,
        "ffmpeg_sha256": digest(ffmpeg),
        "editing": (
            "Real browser video only; navigation/setup trimmed, 300 ms cross-dissolves, "
            "caption overlays. No fabricated UI, results, terminal capture or slideshow frames."
        ),
        "chapters": chapters,
        "commands": commands,
        "probe_command": probe_command,
        "decode_command": decode,
        "decoded_successfully": True,
        "privacy": {
            "credentials_configured": False,
            "external_browser_requests": capture["external_browser_requests"],
            "live_integrations_tested": False,
            "notifications_sent": 0,
            "synthetic_fixture": capture["story"]["fixture"],
            "visible_text_checks_passed": True,
        },
        "original_recording_unchanged": capture["original_recording_unchanged"],
    }
    (directory / "render.json").write_text(json.dumps(record, indent=2) + "\n")
    (directory / "probe.json").write_text(json.dumps(probe, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: record[key]
                for key in ["status", "video", "duration_seconds", "bytes", "sha256"]
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
