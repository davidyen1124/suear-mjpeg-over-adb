# Observed Suear video protocol

These notes describe the packet format observed with Suear app 1.1.132 and the tested camera. The independent client implements video registration and reception; it does not implement device settings, firmware updates, or the complete control protocol.

## Endpoints

| Purpose | Camera endpoint | Transport |
|---|---|---|
| Video registration and video source | `192.168.1.1:10006` | UDP |
| Information queries used by the official app | `192.168.1.1:10005` | UDP |
| Periodic status | Camera source port `51569` → phone port `10007` in the observed session | UDP |

The camera also acts as the phone's Wi-Fi gateway. Its observed phone address was in `192.168.1.0/24`. The phone receive port is allocated dynamically and must be included in the video registration request.

The active video stream is JPEG over custom UDP. It is not a standard RTSP, RTP, or HTTP stream.

## Video registration

The official app sent two information queries to UDP `10005`, followed by a 16-byte video registration request to UDP `10006`. The independent client successfully received video using the registration request alone.

Numeric fields are little-endian:

| Offset | Bytes | Observed field |
|---|---:|---|
| 0 | 4 | Magic `EE FF EE FF` |
| 4 | 2 | Request sequence; the client starts at `2` |
| 6 | 2 | Command `4`, observed video registration/start |
| 8 | 2 | Observed request field `1` |
| 10 | 2 | Declared payload size `2` |
| 12 | 2 | Phone UDP receive port |
| 14 | 2 | Zero padding, matching the observed 16-byte request |

The helper binds a UDP socket to the phone's Wi-Fi IPv4 address, writes that socket's allocated port into the request, and sends it to the camera. Video then arrives from the camera's UDP port `10006` at the registered phone port.

The official app also sent periodic traffic to UDP `52219` and `44506`, plus a discovery broadcast. Their full meaning is unconfirmed. The minimal client streamed for 60 seconds without sending those messages, so the independent viewer does not reproduce them as speculative keepalives.

After three seconds without video, the helper retries registration no more often than once every three seconds. It does not query the other endpoints or send camera setting commands.

## Video fragments

Each UDP video payload starts with a 16-byte custom header. Full-size payloads in the inspected capture were 1,296 bytes: 16 header bytes and 1,280 JPEG bytes. The last fragment may be shorter and may contain padding after the JPEG end marker.

| Offset | Observed meaning |
|---|---|
| 0 | `01` in tested video packets |
| 1 | Packet counter, increasing modulo 256 |
| 2 | Frame counter, constant within a JPEG and advancing for the next frame |
| 3 | `00` for intermediate fragments; `01` for the final fragment |
| 4 | Matches the fragment count in inspected complete frames |
| 5–11 | Additional metadata, not fully decoded |
| 12–15 | Observed `80 02 E0 01`; resembles little-endian 640×480, although the decoded JPEG is 480×480. Not used as image dimensions. |
| 16 onward | JPEG fragment |

The first fragment begins with JPEG SOI `FF D8`. Concatenate the bytes from offset 16 in packet-counter order for the same frame counter. In the final fragment, truncate after JPEG EOI `FF D9` to remove padding.

A missing or out-of-order packet discards the current frame. The next JPEG SOI resynchronizes the decoder. An immediate duplicate packet is ignored. Frame assembly is capped at 4 MiB.

The initial clean capture produced 170 complete JPEGs from 2,217 video packets, with approximately 17.2 frames per second. FFprobe decoded all 170 frames as MJPEG, 480×480. Those diagnostic camera images and captures are not included in this repository.

The official app applies display transforms such as cropping, rotation, a circular mask, and optional mirroring. The browser viewer displays the original square JPEG and provides manual rotation and mirror controls.

## USB framing used by this project

This framing is part of this project's helper, not part of the camera protocol. `adb exec-out` carries the helper's stdout over USB. Remote stderr is redirected to a temporary log so diagnostics cannot corrupt the binary stream.

The helper begins with a 14-byte header:

| Bytes | Field |
|---:|---|
| 8 | ASCII magic `SUEAR01\n` |
| 4 | Phone IPv4 address in network order |
| 2 | Phone receive port in network order |

Each following record contains a two-byte unsigned network-order length, then that many UDP payload bytes. A zero-length record is an idle USB heartbeat; it is not sent to the camera.

The helper filters for the configured camera source address/port and the observed video payload format. Python reads whole records, reassembles JPEGs, and serves them as standard HTTP `multipart/x-mixed-replace` MJPEG.

## Remaining unknowns

- Full device status/control semantics and additional header metadata.
- A command to stop camera transmission when the receiver closes.
- Startup behavior immediately after a full camera power-cycle.
- Behavior during prolonged Android deep sleep or on other firmware/models.

The confirmed result is independent registration and playback with the official app stopped, including recovery after the phone reconnects to camera Wi-Fi.
