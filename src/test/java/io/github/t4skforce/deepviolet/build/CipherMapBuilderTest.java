package io.github.t4skforce.deepviolet.build;

import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.github.t4skforce.deepviolet.util.Downloader;

import org.mockito.MockedStatic;
import static org.mockito.Mockito.*;

class CipherMapBuilderTest {

  @Test
  void testFetch() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenReturn(null);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL))).thenReturn(null);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL))).thenReturn(null);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenReturn(null);
      

      assertTrue(CipherMapBuilder.builder().fetch().build().isEmpty());
    }    
  }

}
