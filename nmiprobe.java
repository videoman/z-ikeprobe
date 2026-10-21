// NmiProbe.java - raw AF_UNIX probe for z/OS IKED NMI (or any unix socket)
//
// Requires Java 16+ (AF_UNIX SocketChannel). Java 11+ runs it without javac:
//   java NmiProbe.java <sockpath> [hexbytes|-] [padlen] [timeout_sec]
//
// Examples:
//   java NmiProbe.java /var/ike/iked.sock -                 # listen only
//   java NmiProbe.java /var/ike/iked.sock 00 64             # 64 zero bytes
//   java NmiProbe.java /var/ike/iked.sock D5D4A287 64       # EBCDIC "NMsg" + pad

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.file.Path;

public class NmiProbe {
    static final Charset EBCDIC = Charset.forName("IBM1047");

    static void dump(byte[] p, int n, long base) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i += 16) {
            sb.append(String.format("%08X  ", base + i));
            for (int j = 0; j < 16; j++) {
                if (i + j < n) sb.append(String.format("%02X", p[i + j] & 0xff));
                else sb.append("  ");
                if (j % 4 == 3) sb.append(' ');
            }
            sb.append(" |");
            for (int j = 0; j < 16 && i + j < n; j++) {
                char c = new String(p, i + j, 1, EBCDIC).charAt(0);
                sb.append(c >= 0x20 && c < 0x7f ? c : '.');
            }
            sb.append("|  a:");
            for (int j = 0; j < 16 && i + j < n; j++) {
                int b = p[i + j] & 0xff;
                sb.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
            }
            sb.append('\n');
        }
        System.out.print(sb);
    }

    public static void main(String[] a) throws IOException {
        if (a.length < 1) {
            System.err.println("usage: java NmiProbe.java <sockpath> [hexbytes|-] [padlen] [timeout]");
            System.exit(2);
        }
        String path = a[0];
        String hex = a.length > 1 ? a[1] : "-";
        int pad = a.length > 2 ? Integer.parseInt(a[2]) : 0;
        int timeout = a.length > 3 ? Integer.parseInt(a[3]) : 5;

        byte[] raw = new byte[0];
        if (!hex.equals("-")) {
            if (hex.length() % 2 != 0) { System.err.println("odd number of hex digits"); System.exit(2); }
            raw = new byte[hex.length() / 2];
            for (int i = 0; i < raw.length; i++)
                raw[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        byte[] req = new byte[Math.max(raw.length, pad)];
        System.arraycopy(raw, 0, req, 0, raw.length);

        SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX);
        try {
            ch.connect(UnixDomainSocketAddress.of(Path.of(path)));
        } catch (IOException e) {
            System.err.println("connect(" + path + "): " + e);
            System.exit(1);
        }
        System.out.println("[+] connected to " + path);

        if (req.length > 0) {
            ByteBuffer out = ByteBuffer.wrap(req);
            while (out.hasRemaining()) ch.write(out);
            System.out.println("[>] sent " + req.length + " bytes:");
            dump(req, req.length, 0);
        }

        ch.configureBlocking(false);
        Selector sel = Selector.open();
        ch.register(sel, SelectionKey.OP_READ);
        ByteBuffer in = ByteBuffer.allocate(65536);
        long total = 0;
        while (true) {
            if (sel.select(timeout * 1000L) == 0) {
                System.out.println("[*] timeout after " + timeout + "s");
                break;
            }
            sel.selectedKeys().clear();
            in.clear();
            int n;
            try {
                n = ch.read(in);
            } catch (IOException e) {
                System.out.println("[*] read error: " + e);
                break;
            }
            if (n < 0) { System.out.println("[*] peer closed connection"); break; }
            if (n == 0) continue;
            System.out.println("[<] recv " + n + " bytes (offset " + total + "):");
            dump(in.array(), n, total);
            total += n;
        }
        System.out.println("[*] total received: " + total + " bytes");
        ch.close();
    }
}
