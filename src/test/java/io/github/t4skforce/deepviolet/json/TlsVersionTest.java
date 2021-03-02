package io.github.t4skforce.deepviolet.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import io.github.t4skforce.deepviolet.protocol.tls.TlsVersion;

import org.junit.jupiter.api.Test;

class TlsVersionTest {

  @Test
  void tlsVersionOfIntTest() {
    assertEquals("TLSv1", TlsVersion.TLS_V1.getName());
    assertEquals(0x0301, TlsVersion.TLS_V1.getVersion());
    assertEquals("TLSv1.1", TlsVersion.TLS_V1_1.getName());
    assertEquals("TLSv1.9", TlsVersion.of(0x030A).getName());
    assertEquals("UNKNOWN_VERSION:0xFFFF", TlsVersion.UNKNOWN.getName());
  }

  @Test
  void tlsVersionOfStringTest() {
    assertEquals("TLSv1", TlsVersion.of("TLSv1").getName());

    assertEquals("TLSv1.1", TlsVersion.of("TLSv1.1").getName());

    assertEquals("TLSv1.9", TlsVersion.of("TLSv1.9").getName());

    assertEquals(TlsVersion.UNKNOWN.getName(), TlsVersion.of("TLSv1.10").getName());

    assertEquals(TlsVersion.UNKNOWN.getName(),
        TlsVersion.of("TLSv1." + Integer.MAX_VALUE).getName());

    assertEquals(TlsVersion.UNKNOWN.getName(), TlsVersion.of("TLSv1." + Long.MAX_VALUE).getName());

    assertEquals("SSLv2", TlsVersion.of("SSLv2").getName());

    assertEquals("SSLv3", TlsVersion.of("SSLv3").getName());

    assertEquals(TlsVersion.UNKNOWN.getName(), TlsVersion.of("UNKNOWN").getName());

    assertEquals(TlsVersion.UNKNOWN.getName(), TlsVersion.of((String) null).getName());

    assertEquals(TlsVersion.UNKNOWN.getName(), TlsVersion.of("").getName());
  }

  @Test
  void tlsVersionHashCodeTest() {
    assertEquals(801, TlsVersion.TLS_V1_1.hashCode());
    assertEquals(802, TlsVersion.TLS_V1_2.hashCode());
    assertEquals(803, TlsVersion.TLS_V1_3.hashCode());
    assertEquals(809, TlsVersion.of("TLSv1.9").hashCode());
  }

  @Test
  void tlsVersionEqualsTest() {
    assertEquals(TlsVersion.TLS_V1_1, TlsVersion.of("TLSv1.1"));
    assertNotEquals(TlsVersion.TLS_V1_1, TlsVersion.of("TLSv1.2"));
    assertNotEquals(null, TlsVersion.TLS_V1_1);
    assertNotEquals(new Object(), TlsVersion.TLS_V1_1);
  }

  @Test
  void tlsVersionToStringTest() {
    assertEquals("TLSv1 (0x0301)", TlsVersion.TLS_V1.toString());
    assertEquals("SSLv2 (0x0200)", TlsVersion.SSL_V2.toString());
    assertEquals("SSLv3 (0x0300)", TlsVersion.SSL_V3.toString());
    assertEquals("UNKNOWN_VERSION:0xFFFF (0xFFFF)", TlsVersion.UNKNOWN.toString());
  }

}
