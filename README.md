# suear-mjpeg-over-adb

View a Suear camera on your computer through a USB-connected, rooted Android phone—**without opening or running the Suear app**.

The Python viewer launches a small helper on the phone. That helper registers its own video receive port with the camera, receives the JPEG fragments over Wi-Fi, and sends them over USB. Python reassembles the frames and serves a local browser viewer and MJPEG stream.

## Requirements

- Python 3.9 or newer on the computer. Only the standard library is used.
- Android `adb` installed and available on your `PATH`.
- A rooted Android phone with USB debugging authorized and `su` available.
- The phone connected to the Suear camera's Wi-Fi and to the computer over USB.

The compiled Android helper is included. You do not need a Java compiler, Android SDK, or `tcpdump` for normal use. No Android app is installed by this tool.

## Quick start

```sh
git clone https://github.com/davidyen1124/suear-mjpeg-over-adb.git
cd suear-mjpeg-over-adb
python3 suear_viewer.py --open
```

Open **http://127.0.0.1:8765/**. The viewer includes rotation, mirroring, fullscreen, and live connection status.

Keep `suear-usb-client.jar` beside `suear_viewer.py`. On macOS, you can also double-click **Start Suear Viewer.command**. Stop the viewer with **Ctrl-C** in its terminal.

If more than one Android device is attached:

```sh
adb devices
python3 suear_viewer.py --serial DEVICE_SERIAL --open
```

Keep the official Suear app closed while using this receiver. Opening it may register a competing video destination. The phone only needs to maintain the camera's Wi-Fi connection and the USB connection.

## How it works

```text
Suear camera 192.168.1.1:10006
       │ custom UDP / JPEG fragments over Wi-Fi
       ▼
Android helper with its own receive socket
       │ datagrams framed over USB via adb exec-out
       ▼
Python JPEG reassembler
       │ HTTP multipart MJPEG on 127.0.0.1
       ▼
Browser or media player
```

The helper opens a UDP socket on the phone's Wi-Fi interface and sends the camera a 16-byte registration request containing that socket's receive port. It receives video directly; it does not load Suear's code or read another app's sockets.

The camera's tested video source is `192.168.1.1:10006/UDP`. Each video packet has a custom 16-byte header followed by a JPEG fragment. The decoder tracks frame and packet counters, discards incomplete frames, and resynchronizes at the next JPEG start. The tested stream is 480×480 at approximately 17 fps under good Wi-Fi conditions.

When video stops, the helper retries registration at most once every three seconds. When the phone loses its Wi-Fi address, the viewer waits and starts a fresh receiver after reconnection. It does not change Wi-Fi settings during normal operation.

See [PROTOCOL.md](PROTOCOL.md) for the observed startup request, video packet format, and USB framing.

## Options

```sh
python3 suear_viewer.py --help
```

| Option | Default | Purpose |
|---|---|---|
| `--serial` | ADB's selected device | Select a USB-connected phone |
| `--device-ip` | `192.168.1.1` | Camera IP address |
| `--video-port` | `10006` | Camera UDP port |
| `--iface` | `wlan0` | Phone Wi-Fi interface |
| `--port` | `8765` | Local HTTP port |
| `--open` | Off | Open the browser automatically |
| `--passive` | Off | Capture an existing stream with the phone's `tcpdump` instead of starting a direct receiver |

For example:

```sh
python3 suear_viewer.py --serial DEVICE_SERIAL --port 8099 --open
```

Configuration uses these command-line options. The default viewer port is now `8765`.

## HTTP endpoints

All endpoints listen on **127.0.0.1** only.

| Path | Purpose |
|---|---|
| `/` | Browser viewer |
| `/stream.mjpg` | Continuous multipart MJPEG stream |
| `/mjpeg` | Alias for `/stream.mjpg` |
| `/frame.jpg` | Latest live JPEG; returns HTTP 503 when stale |
| `/status.json` | Mode, connection status, FPS, frame count, drops, and endpoints |

For a media player:

```sh
ffplay -fflags nobuffer -flags low_delay -framedrop http://127.0.0.1:8765/stream.mjpg
```

Frames are displayed locally and are not recorded. Memory holds the latest complete image and the frame currently being assembled.

## Phone helper and cleanup

The viewer copies the small helper JAR to `/data/local/tmp/suear-usb-client-<hash>.jar` and runs it through Android's built-in `app_process` under `su`. This is a process for the current viewing session, not an installed APK or persistent service.

Normal shutdown stops that helper and removes its temporary PID/log files. The reusable JAR remains in `/data/local/tmp`. Default mode does not create packet capture files, ADB forwarding rules, or a network listener on the phone.

## Development

```text
suear_viewer.py                Python receiver, JPEG decoder, and HTTP viewer
suear-usb-client.jar           Bundled Android DEX helper
android/SuearUsbClient.java    Helper source
scripts/build_android_client.py
                              Rebuilds the helper from source
tests/test_viewer.py           Tests using synthetic protocol data
PROTOCOL.md                   Observed protocol details
Start Suear Viewer.command     Optional macOS launcher
```

Run the tests without a phone:

```sh
python3 -m unittest discover -s tests -v
```

To rebuild the helper, install a JDK that supports `javac --release 8` and Android SDK Build-Tools, then run:

```sh
python3 scripts/build_android_client.py
```

The build script finds `d8` on `PATH`, in `ANDROID_HOME`/`ANDROID_SDK_ROOT`, or in common SDK locations. You can supply it explicitly:

```sh
python3 scripts/build_android_client.py --d8 /path/to/android-sdk/build-tools/36.0.0/d8
```

The helper is compiled for Android API 26 or newer. The included JAR is built from the checked-in Java source.

## Validation and limitations

Verified on a rooted Pixel 4 XL with a Suear camera and Suear app version 1.1.132:

- Independent video registration and playback with Suear force-stopped.
- A 60-second session with only the initial video registration, without the app's periodic control messages.
- Automatic recovery after phone Wi-Fi was disabled and re-enabled, with Suear still stopped.
- Successful FFmpeg decoding of the reconstructed JPEGs and the direct HTTP stream.
- Cleanup of the phone helper on normal viewer shutdown.

A full camera power-cycle and long-duration Android deep sleep have not been independently verified. Other camera models or firmware versions may use a different protocol. The decoder currently drops out-of-order or incomplete frames instead of recovering missing packets.

A camera stop-stream command is not implemented. After the viewer stops, the camera may continue transmitting to the former port until another receiver registers or the camera is powered off.

If the viewer says it is waiting for the camera, check `adb devices`, root access, and the phone's Wi-Fi connection. `/status.json` reports the latest receiver error. If the HTTP port is already in use, open the existing viewer or select another `--port`.

License: ISC.
