package io.github.t4skforce.deepviolet.server;

import static org.junit.Assert.assertTrue;

import io.github.t4skforce.deepviolet.protocol.tls.server.SimpleTlsServer;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsHelloExchange;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsHelloHandler;
import io.github.t4skforce.deepviolet.test.extension.SimpleTlsServerExtension;
import io.github.t4skforce.deepviolet.test.extension.SimpleTlsServerExtension.SimpleTlsServerConfig;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import org.junit.Ignore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SimpleTlsServerExtension.class)
class SimpleTlsServerTest {

  private final static byte[] CLIENT_HELLO_TLS_1_0 = new byte[] {
      // Record Header
      (byte) 0x16, // type is 0x16 (handshake record)
      (byte) 0x03, (byte) 0x01, // protocol version is 3.1 (also known as TLS 1.0)
      (byte) 0x00, (byte) 0xA5, // 0xA5 (165) bytes of handshake message follows
      // Handshake Header
      (byte) 0x01, // handshake message type 0x01 (client hello)
      (byte) 0x00, (byte) 0x00, (byte) 0xa1, // 0xA1 (161) bytes of client hello follows
      // Client Version
      (byte) 0x03, (byte) 0x03, // The protocol version of "3,3" (meaning TLS 1.2) is given.
      // Client Random
      (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
      (byte) 0x0f, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
      (byte) 0x1e, (byte) 0x1f, // The client provides 32 bytes of random
                                // data. In this example we've made the
                                // random data a predictable string.
      // Session ID
      (byte) 0x00, // 00 - length of zero (no session id is provided)
      // Cipher Suites
      (byte) 0x00, (byte) 0x20, // 00 20 - 0x20 (32) bytes of cipher suite data
      (byte) 0xcc, (byte) 0xa8, // cc a8 - assigned value for
                                // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      (byte) 0xcc, (byte) 0xa9, // cc a9 - assigned value for
                                // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      (byte) 0xc0, (byte) 0x2f, // c0 2f - assigned value for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      (byte) 0xc0, (byte) 0x30, // c0 30 - assigned value for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      (byte) 0xc0, (byte) 0x2b, // c0 2b - assigned value for
                                // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      (byte) 0xc0, (byte) 0x2c, // c0 2c - assigned value for
                                // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      (byte) 0xc0, (byte) 0x13, // c0 13 - assigned value for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
      (byte) 0xc0, (byte) 0x09, // c0 09 - assigned value for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
      (byte) 0xc0, (byte) 0x14, // c0 14 - assigned value for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      (byte) 0xc0, (byte) 0x0a, // c0 0a - assigned value for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
      (byte) 0x00, (byte) 0x9c, // 00 9c - assigned value for TLS_RSA_WITH_AES_128_GCM_SHA256
      (byte) 0x00, (byte) 0x9d, // 00 9d - assigned value for TLS_RSA_WITH_AES_256_GCM_SHA384
      (byte) 0x00, (byte) 0x2f, // 00 2f - assigned value for TLS_RSA_WITH_AES_128_CBC_SHA
      (byte) 0x00, (byte) 0x35, // 00 35 - assigned value for TLS_RSA_WITH_AES_256_CBC_SHA
      (byte) 0xc0, (byte) 0x12, // c0 12 - assigned value for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
      (byte) 0x00, (byte) 0x0a, // 00 0a - assigned value for TLS_RSA_WITH_3DES_EDE_CBC_SHA
      // Compression Methods
      (byte) 0x01, // 01 - 0x1 (1) bytes of compression methods follows
      (byte) 0x00, // 00 - assigned value for no compression
      // Extensions Length
      (byte) 0x00, (byte) 0x58, // 00 58 - the extensions will take 0x58 (88) bytes of data
      // Extension - Server Name
      (byte) 0x00, (byte) 0x00, // 00 00 - assigned value for extension "server name"
      (byte) 0x00, (byte) 0x18, // 00 18 - 0x18 (24) bytes of "server name" extension data follows
      (byte) 0x00, (byte) 0x16, // 00 16 - 0x16 (22) bytes of first (and only) list entry follows
      (byte) 0x00, // 00 - list entry is type 0x00 "DNS hostname"
      (byte) 0x00, (byte) 0x13, // 00 13 - 0x13 (19) bytes of hostname follows
      (byte) 0x65, (byte) 0x78, (byte) 0x61, (byte) 0x6d, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x2e, (byte) 0x75, (byte) 0x6c, (byte) 0x66, (byte) 0x68, (byte) 0x65, (byte) 0x69, (byte) 0x6d,
      (byte) 0x2e, (byte) 0x6e, (byte) 0x65, (byte) 0x74, // 65 78 61 ... 6e 65 74 -
                                                          // "example.ulfheim.net"
      // Extension - Status Request
      (byte) 0x00, (byte) 0x05, // 00 05 - assigned value for extension "status request"
      (byte) 0x00, (byte) 0x05, // 00 05 - 0x5 (5) bytes of "status request" extension data follows
      (byte) 0x01, // 01 - assigned value for "certificate status type: OCSP"
      (byte) 0x00, (byte) 0x00, // 00 00 - 0x0 (0) bytes of responderID information
      (byte) 0x00, (byte) 0x00, // 00 00 - 0x0 (0) bytes of request extension information
      // Extension - Supported Groups
      (byte) 0x00, (byte) 0x0a, // 00 0a - assigned value for extension "supported groups"
      (byte) 0x00, (byte) 0x0a, // 00 0a - 0xA (10) bytes of "supported groups" extension data
                                // follows
      (byte) 0x00, (byte) 0x08, // 00 08 - 0x8 (8) bytes of data are in the curves list
      (byte) 0x00, (byte) 0x1d, // 00 1d - assigned value for the curve "x25519"
      (byte) 0x00, (byte) 0x17, // 00 17 - assigned value for the curve "secp256r1"
      (byte) 0x00, (byte) 0x18, // 00 18 - assigned value for the curve "secp384r1"
      (byte) 0x00, (byte) 0x19, // 00 19 - assigned value for the curve "secp521r1"
      // Extension - EC Point Formats
      (byte) 0x00, (byte) 0x0b, // 00 0b - assigned value for extension "EC points format"
      (byte) 0x00, (byte) 0x02, // 00 02 - 0x2 (2) bytes of "EC points format" extension data
                                // follows
      (byte) 0x01, // 01 - 0x1 (1) bytes of data are in the supported formats list
      (byte) 0x00, // 00 - assigned value for uncompressed form
      // Extension - Signature Algorithms
      (byte) 0x00, (byte) 0x0d, // 00 0d - assigned value for extension "Signature Algorithms"
      (byte) 0x00, (byte) 0x12, // 00 12 - 0x12 (18) bytes of "Signature Algorithms" extension data
                                // follows
      (byte) 0x00, (byte) 0x10, // 00 10 - 0x10 (16) bytes of data are in the following list of
                                // algorithms
      (byte) 0x04, (byte) 0x01, // 04 01 - assigned value for RSA/PKCS1/SHA256
      (byte) 0x04, (byte) 0x03, // 04 03 - assigned value for ECDSA/SECP256r1/SHA256
      (byte) 0x05, (byte) 0x01, // 05 01 - assigned value for RSA/PKCS1/SHA386
      (byte) 0x05, (byte) 0x03, // 05 03 - assigned value for ECDSA/SECP384r1/SHA384
      (byte) 0x06, (byte) 0x01, // 06 01 - assigned value for RSA/PKCS1/SHA512
      (byte) 0x06, (byte) 0x03, // 06 03 - assigned value for ECDSA/SECP521r1/SHA512
      (byte) 0x02, (byte) 0x01, // 02 01 - assigned value for RSA/PKCS1/SHA1
      (byte) 0x02, (byte) 0x03, // 02 03 - assigned value for ECDSA/SHA1
      // Extension - Renegotiation Info
      (byte) 0xff, (byte) 0x01, // ff 01 - assigned value for extension "Renegotiation Info"
      (byte) 0x00, (byte) 0x01, // 00 01 - 0x1 (1) bytes of "Renegotiation Info" extension data
                                // follows
      (byte) 0x00, // 00 - length of renegotiation data is zero, because this is a new connection
      // Extension - SCT
      (byte) 0x00, (byte) 0x12, // 00 12 - assigned value for extension "signed certificate
                                // timestamp"
      (byte) 0x00, (byte) 0x00 // 00 00 - 0x0 (0) bytes of "signed certificate timestamp" extension
                               // data follows
  };

  @Ignore
  @Test
  @SimpleTlsServerConfig(port = 5000)
  void testExternal(SimpleTlsServer server) throws Exception {
    System.out.println(server.getHost() + ":" + server.getPort());
    Thread.sleep(300000);
  }

  @Test
  @SimpleTlsServerConfig(port = 5000)
  void test(SimpleTlsServer server) throws Exception {
//    System.out.println(server.getHost() + ":" + server.getPort());
//    Thread.sleep(300000);

    server.handler(new TlsHelloHandler() {
      @Override
      public void handle(TlsHelloExchange exchange) throws IOException {
        assertTrue("ClientHello is invalid", exchange.getClientHello().isValid());
      }
    });

    InetAddress ip = InetAddress.getByName(server.getHost());
    Socket socket = new Socket(ip, server.getPort());

    try (DataInputStream in = new DataInputStream(socket.getInputStream()); DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
      out.write(CLIENT_HELLO_TLS_1_0);
      in.readAllBytes();
      assertTrue(true);
    }

  }

}
