import argparse
import http.client
import io
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from suear_viewer import Camera, Reassembler, handler_for, pcap_packets, read_exact, video_payload


DEVICE = socket.inet_aton('192.168.1.1')
PHONE = socket.inet_aton('192.168.1.10')
# Synthetic marker-delimited data for protocol tests, not a recorded camera image.
JPEG = b'\xff\xd8synthetic-frame-data\xff\xd9'


def fragment(sequence, frame_id, payload, final=False):
    return bytes([1, sequence, frame_id, int(final)]) + bytes(12) + payload


def datagram(payload, source=DEVICE, port=10006, fragmented=False):
    udp = struct.pack('!HHHH', port, 44000, len(payload) + 8, 0) + payload
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack('!H', len(udp) + 20)
    ip[6:8] = struct.pack('!H', 0x2000 if fragmented else 0)
    ip[9] = 17
    ip[12:16] = source
    ip[16:20] = PHONE
    return bytes(12) + b'\x08\x00' + ip + udp


class ShortReads(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 3) if size >= 0 else 3)


class ReassemblyTests(unittest.TestCase):
    def test_sequence_wrap_and_final_padding(self):
        decoder = Reassembler()
        self.assertIsNone(decoder.feed(fragment(254, 8, JPEG[:6])))
        self.assertIsNone(decoder.feed(fragment(255, 8, JPEG[6:12])))
        self.assertEqual(decoder.feed(fragment(0, 8, JPEG[12:] + b'\0\0', True)), JPEG)
        self.assertEqual(decoder.dropped, 0)

    def test_lost_fragment_discards_frame_then_recovers(self):
        decoder = Reassembler()
        decoder.feed(fragment(10, 1, JPEG[:6]))
        self.assertIsNone(decoder.feed(fragment(12, 1, JPEG[12:], True)))
        self.assertEqual(decoder.dropped, 1)
        self.assertEqual(decoder.feed(fragment(13, 2, JPEG, True)), JPEG)

    def test_duplicate_packet_is_ignored(self):
        decoder = Reassembler()
        first = fragment(20, 4, JPEG[:10])
        decoder.feed(first)
        self.assertIsNone(decoder.feed(first))
        self.assertEqual(decoder.feed(fragment(21, 4, JPEG[10:], True)), JPEG)
        self.assertEqual(decoder.dropped, 0)

    def test_missing_soi_and_missing_eoi_do_not_produce_frames(self):
        decoder = Reassembler()
        self.assertIsNone(decoder.feed(fragment(0, 0, b'mid-frame', True)))
        self.assertIsNone(decoder.feed(fragment(1, 1, b'\xff\xd8unfinished', True)))
        self.assertEqual(decoder.dropped, 1)

    def test_missing_last_fragment_resynchronizes_on_next_frame(self):
        decoder = Reassembler()
        decoder.feed(fragment(4, 7, JPEG[:8]))
        self.assertEqual(decoder.feed(fragment(8, 8, JPEG, True)), JPEG)
        self.assertEqual(decoder.dropped, 1)

    def test_out_of_order_fragment_is_not_joined(self):
        decoder = Reassembler()
        decoder.feed(fragment(40, 8, JPEG[:6]))
        self.assertIsNone(decoder.feed(fragment(39, 8, JPEG[6:], True)))
        self.assertEqual(decoder.dropped, 1)

    def test_incomplete_frame_memory_is_bounded(self):
        decoder = Reassembler()
        self.assertIsNone(decoder.feed(fragment(0, 0, b'\xff\xd8' + bytes(4 * 1024 * 1024))))
        self.assertIsNone(decoder.active)
        self.assertEqual(decoder.dropped, 1)


class TransportTests(unittest.TestCase):
    def test_read_exact_handles_short_usb_reads(self):
        self.assertEqual(read_exact(ShortReads(b'12345678'), 8), b'12345678')
        with self.assertRaises(EOFError):
            read_exact(ShortReads(b'123'), 4)

    def test_usb_records_skip_heartbeat_and_preserve_endpoint(self):
        args = argparse.Namespace(adb='adb', serial=None, passive=False, device_ip='192.168.1.1',
                                  video_port=10006, iface='wlan0')
        camera = Camera(args)
        payload = fragment(1, 1, JPEG, True)
        wire = b'SUEAR01\n' + PHONE + struct.pack('!H', 44000)
        wire += b'\0\0' + struct.pack('!H', len(payload)) + payload
        camera.process = argparse.Namespace(stdout=ShortReads(wire))
        records = camera.receive_payloads()
        self.assertEqual(next(records), (payload, '192.168.1.10', 44000))
        self.assertEqual(camera.phone_endpoint, '192.168.1.10:44000')
        with self.assertRaises(EOFError):
            next(records)

    def test_usb_rejects_unexpected_header(self):
        args = argparse.Namespace(adb='adb', serial=None, passive=False, device_ip='192.168.1.1',
                                  video_port=10006, iface='wlan0')
        camera = Camera(args)
        camera.process = argparse.Namespace(stdout=io.BytesIO(bytes(14)))
        with self.assertRaises(ValueError):
            next(camera.receive_payloads())

    def test_udp_filters_source_and_rejects_ip_fragments(self):
        payload = fragment(1, 1, JPEG, True)
        self.assertEqual(video_payload(datagram(payload), DEVICE, 10006),
                         (payload, '192.168.1.10', 44000))
        for packet in (datagram(payload, source=PHONE), datagram(payload, port=10005),
                       datagram(payload, fragmented=True), datagram(payload)[:-1]):
            self.assertIsNone(video_payload(packet, DEVICE, 10006))

    def test_pcap_endianness_and_short_reads(self):
        packet = datagram(fragment(0, 0, JPEG, True))
        for endian, magic in (('<', b'\xd4\xc3\xb2\xa1'), ('>', b'\xa1\xb2\xc3\xd4')):
            with self.subTest(endian=endian):
                header = magic + struct.pack(endian + 'HHIIII', 2, 4, 0, 0, 1600, 1)
                record = struct.pack(endian + 'IIII', 1000, 0, len(packet), len(packet)) + packet
                packets = pcap_packets(ShortReads(header + record))
                self.assertEqual(next(packets), packet)
                with self.assertRaises(EOFError):
                    next(packets)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        args = argparse.Namespace(adb='adb', serial=None, passive=False, device_ip='192.168.1.1',
                                  video_port=10006, iface='wlan0')
        cls.camera = Camera(args)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(cls.camera))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self):
        with self.camera.condition:
            self.camera.frame = JPEG
            self.camera.frames = 1
            self.camera.last_frame = time.monotonic()
            self.camera.condition.notify_all()

    @classmethod
    def tearDownClass(cls):
        cls.camera.stop.set()
        with cls.camera.condition:
            cls.camera.condition.notify_all()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def connect(self, path):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        connection.request('GET', path)
        return connection, connection.getresponse()

    def test_snapshot_is_current_and_disables_caching(self):
        connection, response = self.connect('/frame.jpg')
        try:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
            self.assertEqual(response.read(), JPEG)
        finally:
            connection.close()

    def test_stale_snapshot_returns_503(self):
        self.camera.last_frame = time.monotonic() - 5
        connection, response = self.connect('/frame.jpg')
        try:
            self.assertEqual(response.status, 503)
            response.read()
        finally:
            connection.close()

    def test_both_mjpeg_paths_serve_framed_images(self):
        for path in ('/stream.mjpg', '/mjpeg'):
            with self.subTest(path=path):
                connection, response = self.connect(path)
                try:
                    self.assertEqual(response.status, 200)
                    self.assertIn('multipart/x-mixed-replace', response.getheader('Content-Type'))
                    self.assertEqual(response.readline(), b'--suear\r\n')
                    self.assertEqual(response.readline(), b'Content-Type: image/jpeg\r\n')
                    self.assertEqual(response.readline(), b'Content-Length: ' + str(len(JPEG)).encode() + b'\r\n')
                    self.assertEqual(response.readline(), b'\r\n')
                    self.assertEqual(response.read(len(JPEG)), JPEG)
                finally:
                    response.close()
                    connection.close()


class CLITests(unittest.TestCase):
    def test_invalid_interface_is_rejected_before_adb(self):
        script = Path(__file__).resolve().parents[1] / 'suear_viewer.py'
        result = subprocess.run([sys.executable, str(script), '--iface', 'wlan0;echo invalid'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn('valid interface name', result.stderr)


if __name__ == '__main__':
    unittest.main()
