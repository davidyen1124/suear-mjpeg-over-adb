#!/usr/bin/env python3
"""Start and view the Suear camera through a rooted USB phone, without Suear.

Python 3 standard library plus the included Android DEX helper. Default mode
registers its own video socket; --passive retains the original capture mode.
HTTP listens on localhost only. No Android app installation is needed.
"""
import argparse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
import uuid
import webbrowser


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError("USB receiver ended; check the phone connection, Wi-Fi, and root access")
        data.extend(chunk)
    return bytes(data)


def pcap_packets(stream):
    header = read_exact(stream, 24)
    magic = header[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Expected PCAP data; verify that root and tcpdump work on the phone")
    link_type = struct.unpack_from(endian + "I", header, 20)[0] & 0xFFFF
    if link_type != 1:
        raise ValueError(f"Unsupported capture link type {link_type}; expected Ethernet on wlan0")
    while True:
        record = read_exact(stream, 16)
        size = struct.unpack_from(endian + "I", record, 8)[0]
        if not 14 <= size <= 262144:
            raise ValueError("Invalid PCAP packet size")
        yield read_exact(stream, size)


def video_payload(packet, device_ip, video_port):
    if len(packet) < 42 or packet[12:14] != b"\x08\x00":
        return None
    ip = packet[14:]
    ihl = (ip[0] & 15) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
        return None
    if ip[12:16] != device_ip or struct.unpack_from("!H", ip, 6)[0] & 0x3FFF:
        return None
    source_port, destination_port, size = struct.unpack_from("!HHH", ip, ihl)
    if source_port != video_port or size < 24 or len(ip) < ihl + size:
        return None
    return ip[ihl + 8:ihl + size], socket.inet_ntoa(ip[16:20]), destination_port


class Reassembler:
    """Observed Suear v1 framing: 16-byte header, ordered JPEG fragments.

    Byte 1: packet counter modulo 256. Byte 2: frame counter modulo 256.
    Byte 3: 1 on the last fragment. Byte 4: fragment count in tested frames.
    Missing/out-of-order fragments discard the current frame, then resync at SOI.
    """
    def __init__(self):
        self.active = None
        self.dropped = 0

    def feed(self, data):
        if len(data) < 18 or data[0] != 1:
            return None
        seq, frame_id, final = data[1:4]
        payload = data[16:]
        if self.active and seq == self.active[1] and frame_id == self.active[0]:
            return None  # Duplicate of the most recently received packet.
        if payload.startswith(b"\xff\xd8"):
            if self.active:
                self.dropped += 1
            self.active = [frame_id, seq, bytearray(payload)]
        elif self.active:
            if frame_id != self.active[0] or seq != (self.active[1] + 1) % 256:
                self.dropped += 1
                self.active = None
                return None
            self.active[1] = seq
            self.active[2].extend(payload)
        if not self.active:
            return None
        if len(self.active[2]) > 4 * 1024 * 1024:
            self.dropped += 1
            self.active = None
            return None
        if final == 1:
            jpeg = bytes(self.active[2])
            self.active = None
            end = jpeg.rfind(b"\xff\xd9")
            if end == -1:
                self.dropped += 1
                return None
            return jpeg[:end + 2]  # Final UDP packet can include padding.
        return None


class Camera:
    def __init__(self, args):
        self.args = args
        self.condition = threading.Condition()
        self.stop = threading.Event()
        self.process = None
        self.adb = [args.adb] + (["-s", args.serial] if args.serial else [])
        self.pidfile = None
        self.remote_log = None
        self.remote_jar = None
        self.frame = None
        self.frames = 0
        self.last_frame = None
        self.times = deque(maxlen=100)
        self.phone_endpoint = None
        self.error = None
        self.decoder = Reassembler()
        self.device_ip = socket.inet_aton(args.device_ip)

    def run(self):
        while not self.stop.is_set():
            try:
                self.decoder.active = None
                with self.condition:
                    self.times.clear()
                unique = uuid.uuid4().hex
                self.pidfile = f"/data/local/tmp/suear-viewer-{unique}.pid"
                self.remote_log = f"/data/local/tmp/suear-viewer-{unique}.log"
                if self.args.passive:
                    command = (f"exec tcpdump -i {self.args.iface} -p -nn --immediate-mode -s 1600 -U -w - "
                               f"udp and src host {self.args.device_ip} and src port {self.args.video_port}")
                else:
                    if not self.remote_jar:
                        jar = Path(__file__).resolve().with_name("suear-usb-client.jar")
                        digest = hashlib.sha256(jar.read_bytes()).hexdigest()[:16]
                        remote_jar = f"/data/local/tmp/suear-usb-client-{digest}.jar"
                        result = subprocess.run(self.adb + ["push", str(jar), remote_jar],
                                                capture_output=True, timeout=15)
                        if result.returncode:
                            raise OSError(result.stderr.decode(errors="replace").strip() or "ADB helper upload failed")
                        self.remote_jar = remote_jar
                    command = (f"CLASSPATH={self.remote_jar} exec app_process / SuearUsbClient "
                               f"{self.args.device_ip} {self.args.video_port} {self.args.iface}")
                # exec-out merges remote stderr with stdout; redirect diagnostics
                # to our own temporary log to keep the binary transport intact.
                remote = f"su -c 'echo $$ > {self.pidfile}; {command} 2>{self.remote_log}'"
                self.process = subprocess.Popen(self.adb + ["exec-out", remote],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL, bufsize=0)
                for data, phone_ip, phone_port in self.receive_payloads():
                    if self.stop.is_set():
                        break
                    jpeg = self.decoder.feed(data)
                    if jpeg:
                        with self.condition:
                            self.frame = jpeg
                            self.frames += 1
                            self.last_frame = time.monotonic()
                            self.times.append(self.last_frame)
                            self.phone_endpoint = f"{phone_ip}:{phone_port}"
                            self.error = None
                            self.condition.notify_all()
            except (EOFError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
                message = str(exc)
                if not self.stop.is_set() and not self.args.passive and self.remote_log:
                    try:
                        result = subprocess.run(self.adb + ["shell", f"su -c 'tail -c 1000 {self.remote_log}'"],
                                                capture_output=True, timeout=3)
                        detail = result.stdout.decode(errors="replace").strip()
                        if detail and "No such file" not in detail:
                            message = detail
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                with self.condition:
                    self.error = message
            finally:
                self.end_capture()
            self.stop.wait(2)

    def receive_payloads(self):
        if self.args.passive:
            for packet in pcap_packets(self.process.stdout):
                result = video_payload(packet, self.device_ip, self.args.video_port)
                if result:
                    yield result
        else:
            header = read_exact(self.process.stdout, 14)
            if header[:8] != b"SUEAR01\n":
                raise ValueError("Invalid USB helper response")
            phone_ip = socket.inet_ntoa(header[8:12])
            phone_port = struct.unpack("!H", header[12:14])[0]
            with self.condition:
                self.phone_endpoint = f"{phone_ip}:{phone_port}"
            while not self.stop.is_set():
                size = struct.unpack("!H", read_exact(self.process.stdout, 2))[0]
                if size:
                    yield read_exact(self.process.stdout, size), phone_ip, phone_port

    def end_capture(self):
        if self.pidfile:
            cleanup = (f"su -c 'p=$(cat {self.pidfile} 2>/dev/null); "
                       'case "$p" in ""|*[!0-9]*) ;; *) '
                       'case "$(readlink /proc/$p/exe 2>/dev/null)" in */tcpdump|*/app_process|*/app_process32|*/app_process64) '
                       'kill -TERM "$p" 2>/dev/null ;; esac ;; esac; '
                       f"rm -f {self.pidfile} {self.remote_log}'")
            try:
                subprocess.run(self.adb + ["shell", cleanup],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
            self.pidfile = None
        process = self.process
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if process.stdout:
                process.stdout.close()

    def status(self):
        with self.condition:
            age = None if self.last_frame is None else time.monotonic() - self.last_frame
            fps = 0
            if age is not None and age < 2 and len(self.times) > 1:
                fps = (len(self.times) - 1) / (self.times[-1] - self.times[0])
            return {"live": age is not None and age < 2,
                    "frames": self.frames, "fps": round(fps, 1),
                    "dropped_frames": self.decoder.dropped,
                    "last_frame_age_seconds": None if age is None else round(age, 2),
                    "device": f"{self.args.device_ip}:{self.args.video_port}",
                    "mode": "passive" if self.args.passive else "direct",
                    "phone": self.phone_endpoint, "error": self.error}


PAGE = b'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Suear live camera</title>
<style>
:root{color-scheme:dark;font:16px system-ui,sans-serif;background:#101214;color:#edf0f1}
body{max-width:850px;margin:auto;padding:24px}header{display:flex;align-items:center;justify-content:space-between;gap:16px}
h1{font-size:22px;font-weight:600}#state{color:#b8c2ca}.live{color:#71e0ad!important}
.view{background:#000;border-radius:12px;aspect-ratio:1;overflow:hidden;display:grid;place-items:center;max-height:72vh;margin:16px auto;width:min(100%,72vh)}
img{width:100%;height:100%;object-fit:contain}button{background:#242a30;color:inherit;border:1px solid #424c56;border-radius:8px;padding:10px 15px;font:inherit;cursor:pointer}button:hover{background:#353e47}button:focus-visible{outline:2px solid #71e0ad}
nav{display:flex;flex-wrap:wrap;gap:8px;justify-content:center}p{color:#b8c2ca;line-height:1.55;font-size:14px}#info{font-variant-numeric:tabular-nums}a{color:#9dccff}
</style>
<header><h1>Suear live camera</h1><span id="state" role="status">Connecting...</span></header>
<div class="view" id="view"><img id="camera" src="/stream.mjpg" alt="Live image from your Suear camera"></div>
<nav aria-label="Camera display controls"><button id="rotate">Rotate 90&#176;</button><button id="mirror" aria-pressed="false">Mirror</button><button id="full">Fullscreen</button></nav>
<p id="info">Waiting for video from the phone.</p>
<p id="instructions">Keep the phone connected to the camera's Wi-Fi and USB. The Suear app can stay closed. Frames are displayed locally and are not recorded.</p>
<p><a href="/stream.mjpg">MJPEG stream for a media player</a></p>
<script>
const camera=document.querySelector('#camera'),state=document.querySelector('#state'),info=document.querySelector('#info');let angle=0,mirror=false;
function transform(){camera.style.transform=`rotate(${angle}deg) scaleX(${mirror?-1:1})`}
document.querySelector('#rotate').onclick=()=>{angle=(angle+90)%360;transform()};
document.querySelector('#mirror').onclick=e=>{mirror=!mirror;e.currentTarget.setAttribute('aria-pressed',mirror);transform()};
document.querySelector('#full').onclick=()=>document.querySelector('#view').requestFullscreen();
camera.onerror=()=>setTimeout(()=>{camera.src='/stream.mjpg?t='+Date.now()},2000);
async function poll(){try{const r=await fetch('/status.json',{cache:'no-store'});const s=await r.json();state.textContent=s.live?'Live - '+s.fps+' fps':'Waiting for camera';state.className=s.live?'live':'';info.textContent=s.error||(s.phone?`${s.mode==='direct'?'Direct receiver':'Passive capture'} | ${s.device} -> phone ${s.phone} -> USB | ${s.frames} frames | ${s.dropped_frames} incomplete frames discarded`:'Connect the phone to the camera Wi-Fi.');document.querySelector('#instructions').textContent=s.mode==='passive'?"Passive mode: Suear must maintain the camera session. Keep USB and the camera Wi-Fi connected.":"Keep the phone connected to the camera's Wi-Fi and USB. The Suear app can stay closed. Frames are displayed locally and are not recorded.";camera.style.opacity=s.live?'1':'.3'}catch{state.textContent='Viewer stopped';state.className='';camera.style.opacity='.3'}setTimeout(poll,1000)}poll();
</script></html>'''


def handler_for(camera):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, body, content_type, code=200):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            try:
                if path == "/":
                    self.reply(PAGE, "text/html; charset=utf-8")
                elif path == "/status.json":
                    self.reply(json.dumps(camera.status()).encode(), "application/json")
                elif path == "/frame.jpg":
                    with camera.condition:
                        frame = camera.frame
                        recent = camera.last_frame and time.monotonic() - camera.last_frame < 2
                    if frame and recent:
                        self.reply(frame, "image/jpeg")
                    else:
                        self.reply(b"Waiting for live camera frames", "text/plain", 503)
                elif path in ("/stream.mjpg", "/mjpeg"):
                    self.connection.settimeout(10)
                    self.send_response(200)
                    self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=suear")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    seen = -1
                    while not camera.stop.is_set():
                        with camera.condition:
                            camera.condition.wait_for(lambda: camera.frames != seen or camera.stop.is_set(), timeout=3)
                            if camera.stop.is_set():
                                break
                            if camera.frame is None or camera.frames == seen:
                                seen = camera.frames
                                continue
                            frame, seen = camera.frame, camera.frames
                        self.wfile.write(b"--suear\r\nContent-Type: image/jpeg\r\nContent-Length: "
                                         + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")
                        self.wfile.flush()
                else:
                    self.reply(b"Not found", "text/plain", 404)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB USB device serial, needed if multiple phones are attached")
    parser.add_argument("--device-ip", default="192.168.1.1")
    parser.add_argument("--video-port", type=int, default=10006)
    parser.add_argument("--port", type=int, default=8765, help="Local HTTP port")
    parser.add_argument("--iface", default="wlan0", help="Phone Wi-Fi interface")
    parser.add_argument("--open", action="store_true", help="Open the viewer in the default browser")
    parser.add_argument("--passive", action="store_true", help="Use the original tcpdump relay of an existing stream")
    args = parser.parse_args()
    try:
        args.device_ip = str(ipaddress.IPv4Address(args.device_ip))
    except ipaddress.AddressValueError:
        parser.error("--device-ip must be an IPv4 address")
    if not all(1 <= port <= 65535 for port in (args.port, args.video_port)):
        parser.error("Ports must be between 1 and 65535")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", args.iface):
        parser.error("--iface must be a valid interface name, such as wlan0")
    args.adb = shutil.which("adb")
    if not args.adb:
        parser.error("adb was not found; install Android platform-tools and add adb to PATH")
    if not args.passive and not Path(__file__).resolve().with_name("suear-usb-client.jar").is_file():
        parser.error("Keep the included suear-usb-client.jar beside this Python script")
    camera = Camera(args)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(camera))
    capture = threading.Thread(target=camera.run, daemon=True)
    capture.start()
    url = f"http://127.0.0.1:{args.port}/"
    mode = "Passive capture: keep the camera session active." if args.passive else "Direct receiver: Suear app is not required."
    print(f"Suear viewer: {url}\n{mode} Stop with Ctrl-C.", flush=True)
    if args.open:
        webbrowser.open(url)
    def interrupt(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        camera.stop.set()
        with camera.condition:
            camera.condition.notify_all()
        if camera.process and camera.process.poll() is None:
            camera.process.terminate()
        capture.join(timeout=8)
        server.server_close()


if __name__ == "__main__":
    main()
