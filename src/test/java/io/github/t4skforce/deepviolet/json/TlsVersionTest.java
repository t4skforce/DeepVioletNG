package io.github.t4skforce.deepviolet.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class TlsVersionTest {

  @Test
  void tlsVersionOfIntTest() {
    assertEquals("TLSv1.0", TlsVersion.of(TlsVersion.TLS_V1).getName());
    assertEquals(0x0301, TlsVersion.of(TlsVersion.TLS_V1).getVersion());
    assertEquals("TLSv1.1", TlsVersion.of(TlsVersion.TLS_V1_1).getName());
    assertEquals("TLSv1.9", TlsVersion.of(0x030A).getName());
    assertEquals("UNKNOWN_VERSION:0xFFFF", TlsVersion.of(TlsVersion.UNKNOWN).getName());
  }

  @Test
  void tlsVersionOfStringTest() {
    assertEquals("TLSv1.0", TlsVersion.of("TLSv1").getName());

    assertEquals("TLSv1.1", TlsVersion.of("TLSv1.1").getName());

    assertEquals("TLSv1.9", TlsVersion.of("TLSv1.9").getName());

    assertEquals("UNKNOWN_NAME:TLSv1.10", TlsVersion.of("TLSv1.10").getName());

    assertEquals("UNKNOWN_NAME:TLSv1." + Integer.MAX_VALUE,
        TlsVersion.of("TLSv1." + Integer.MAX_VALUE).getName());

    assertEquals("UNKNOWN_NAME:TLSv1." + Long.MAX_VALUE,
        TlsVersion.of("TLSv1." + Long.MAX_VALUE).getName());

    assertEquals("SSLv2", TlsVersion.of("SSLv2").getName());

    assertEquals("SSLv3", TlsVersion.of("SSLv3").getName());

    assertEquals("UNKNOWN_NAME:UNKNOWN", TlsVersion.of("UNKNOWN").getName());

    assertEquals("UNKNOWN_NAME:null", TlsVersion.of(null).getName());

    assertEquals("UNKNOWN_NAME:", TlsVersion.of("").getName());
  }

  @Test
  void tlsVersionHashCodeTest() {
    assertEquals(801, TlsVersion.of(TlsVersion.TLS_V1_1).hashCode());
    assertEquals(802, TlsVersion.of(TlsVersion.TLS_V1_2).hashCode());
    assertEquals(803, TlsVersion.of(TlsVersion.TLS_V1_3).hashCode());
    assertEquals(809, TlsVersion.of("TLSv1.9").hashCode());
  }

  @Test
  void tlsVersionEqualsTest() {
    assertEquals(TlsVersion.of(TlsVersion.TLS_V1_1), TlsVersion.of("TLSv1.1"));
    assertNotEquals(TlsVersion.of(TlsVersion.TLS_V1_1), TlsVersion.of("TLSv1.2"));
    assertNotEquals(null, TlsVersion.of(TlsVersion.TLS_V1_1));
    assertFalse(TlsVersion.of(TlsVersion.TLS_V1_1).equals(Integer.valueOf(1)));
  }

  @Test
  void tlsVersionToStringTest() {
    assertEquals("TLSv1.0 (0x0301)", TlsVersion.of(TlsVersion.TLS_V1).toString());
    assertEquals("SSLv2 (0x0200)", TlsVersion.of(TlsVersion.SSL_V2).toString());
    assertEquals("SSLv3 (0x0300)", TlsVersion.of(TlsVersion.SSL_V3).toString());
    assertEquals("UNKNOWN_VERSION:0xFFFF (0xFFFF)", TlsVersion.of(TlsVersion.UNKNOWN).toString());
  }

}
