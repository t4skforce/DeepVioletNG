package io.github.t4skforce.deepviolet.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class TLSVersionTest {

	@Test
	void tlsVersionOfIntTest() {
		assertEquals("TLSv1.0", TLSVersion.of(TLSVersion.TLS_V1).getName());
		assertEquals(0x0301, TLSVersion.of(TLSVersion.TLS_V1).getVersion());
		assertEquals("TLSv1.1", TLSVersion.of(TLSVersion.TLS_V1_1).getName());
		assertEquals("TLSv1.9", TLSVersion.of(0x030A).getName());
		assertEquals("UNKNOWN_VERSION:0xFFFF", TLSVersion.of(TLSVersion.UNKNOWN).getName());
	}

	@Test
	void tlsVersionOfStringTest() {
		assertEquals("TLSv1.0", TLSVersion.of("TLSv1").getName());
		assertEquals("TLSv1.1", TLSVersion.of("TLSv1.1").getName());
		assertEquals("TLSv1.9", TLSVersion.of("TLSv1.9").getName());
		assertEquals("SSLv2", TLSVersion.of("SSLv2").getName());
		assertEquals("SSLv3", TLSVersion.of("SSLv3").getName());
		assertEquals("UNKNOWN_NAME:UNKNOWN", TLSVersion.of("UNKNOWN").getName());
		assertEquals("UNKNOWN_NAME:null", TLSVersion.of(null).getName());
		assertEquals("UNKNOWN_NAME:", TLSVersion.of("").getName());
	}

	@Test
	void tlsVersionHashCodeTest() {
		assertEquals(801, TLSVersion.of(TLSVersion.TLS_V1_1).hashCode());
		assertEquals(802, TLSVersion.of(TLSVersion.TLS_V1_2).hashCode());
		assertEquals(803, TLSVersion.of(TLSVersion.TLS_V1_3).hashCode());
		assertEquals(809, TLSVersion.of("TLSv1.9").hashCode());
	}

	@Test
	void tlsVersionEqualsTest() {
		assertEquals(TLSVersion.of(TLSVersion.TLS_V1_1), TLSVersion.of("TLSv1.1"));
		assertNotEquals(TLSVersion.of(TLSVersion.TLS_V1_1), TLSVersion.of("TLSv1.2"));
		assertNotEquals(null, TLSVersion.of(TLSVersion.TLS_V1_1));
		boolean result = TLSVersion.of(TLSVersion.TLS_V1_1).equals(null);
		assertFalse(result);
	}

	@Test
	void tlsVersionToStringTest() {
		assertEquals("TLSv1.0 (0x0301)", TLSVersion.of(TLSVersion.TLS_V1).toString());
		assertEquals("SSLv2 (0x0200)", TLSVersion.of(TLSVersion.SSL_V2).toString());
		assertEquals("SSLv3 (0x0300)", TLSVersion.of(TLSVersion.SSL_V3).toString());
		assertEquals("UNKNOWN_VERSION:0xFFFF (0xFFFF)", TLSVersion.of(TLSVersion.UNKNOWN).toString());
	}

}
