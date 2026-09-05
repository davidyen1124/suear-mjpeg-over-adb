import java.io.DataOutputStream;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Enumeration;

/** Runs through Android app_process, with no Android app installation.
 * Receives the camera's UDP stream and preserves datagram boundaries over USB.
 * Implements only the observed video registration command, not camera settings.
 */
public final class SuearUsbClient {
    static InetAddress wifiAddress(String interfaceName) throws IOException {
        NetworkInterface wifi = NetworkInterface.getByName(interfaceName);
        if (wifi != null && wifi.isUp()) {
            Enumeration<InetAddress> addresses = wifi.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress address = addresses.nextElement();
                if (address instanceof Inet4Address) return address;
            }
        }
        throw new IOException("Connect the phone to the Suear camera's Wi-Fi (" + interfaceName + " has no IPv4 address)");
    }

    static void register(DatagramSocket socket, InetAddress device, int devicePort, int sequence)
            throws IOException {
        // Same ordinary video-start request observed from Suear. No credentials,
        // settings writes, discovery broadcasts, or firmware operations involved.
        byte[] request = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0xffeeffee).putShort((short)sequence).putShort((short)4)
            .putShort((short)1).putShort((short)2)
            .putShort((short)socket.getLocalPort()).putShort((short)0).array();
        socket.send(new DatagramPacket(request, request.length, device, devicePort));
    }

    static void run(String[] args) throws Exception {
        String interfaceName = args.length > 2 ? args[2] : "wlan0";
        InetAddress local = wifiAddress(interfaceName);
        InetAddress device = InetAddress.getByName(args[0]);
        int devicePort = Integer.parseInt(args[1]);
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(local, 0));
             DataOutputStream output = new DataOutputStream(new FileOutputStream(FileDescriptor.out))) {
            socket.setReceiveBufferSize(1024 * 1024);
            socket.setSoTimeout(1000);
            // 14-byte USB transport header: magic[8], IPv4[4], receive port[2].
            output.writeBytes("SUEAR01\n");
            output.write(local.getAddress());
            output.writeShort(socket.getLocalPort());
            output.flush();
            int sequence = 2;
            register(socket, device, devicePort, sequence++);
            long lastRegister = System.nanoTime(), lastVideo = lastRegister;
            byte[] buffer = new byte[65535];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            while (true) {
                packet.setLength(buffer.length);
                try {
                    socket.receive(packet);
                    int length = packet.getLength();
                    if (packet.getAddress().equals(device) && packet.getPort() == devicePort
                            && length > 16 && buffer[0] == 1) {
                        lastVideo = System.nanoTime();
                        output.writeShort(length);
                        output.write(buffer, 0, length);
                        output.flush();
                    }
                } catch (SocketTimeoutException timeout) {
                    // A zero-length USB record conveys no image. Writing also
                    // discovers a disconnected computer when video has stopped.
                    output.writeShort(0);
                    output.flush();
                    if (!wifiAddress(interfaceName).equals(local)) {
                        throw new IOException("Phone Wi-Fi address changed; reconnecting");
                    }
                }
                long now = System.nanoTime();
                if (now - lastVideo > 3_000_000_000L && now - lastRegister > 3_000_000_000L) {
                    register(socket, device, devicePort, sequence++);
                    lastRegister = now;
                }
            }
        }
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exception error) {
            System.err.println("Suear client: " + error.getMessage());
            System.exit(1);
        }
    }
}
