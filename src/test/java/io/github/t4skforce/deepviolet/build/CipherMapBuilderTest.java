package io.github.t4skforce.deepviolet.build;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.github.t4skforce.deepviolet.json.CipherMapClassificationsJson;
import io.github.t4skforce.deepviolet.json.CipherMapJson;
import io.github.t4skforce.deepviolet.util.Downloader;

import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.google.common.collect.MapDifference;
import com.google.common.collect.Maps;
import com.google.common.io.Resources;

import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;

class CipherMapBuilderTest {

  @Test
  void testFallbackFetch() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenReturn(StringUtils.EMPTY);
      
      // fall back to local resource version if nothing can be fetched
      assertTrue(CipherMapBuilder.builder().fetch().build().keySet().equals(CipherMapBuilder.builder().build().keySet())); 
    }
  }
  
  
  @Test
  void testParseIana() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(new Answer<String>() {
        @Override
        public String answer(InvocationOnMock invocation) throws Throwable {
          return Resources.toString(Resources.getResource("builder/iana.xhtml"), StandardCharsets.UTF_8);
        }
      });
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenReturn(StringUtils.EMPTY);
      
      CipherMapJson data = CipherMapBuilder.builder().fetch().build();
      
      assertEquals(1,data.size());
      assertTrue(data.containsKey("0x00,0x6C")); 
       
    }
  }

}
