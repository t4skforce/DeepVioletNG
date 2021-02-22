package io.github.t4skforce.deepviolet.build;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.t4skforce.deepviolet.json.CipherMapJson;
import io.github.t4skforce.deepviolet.util.Downloader;

import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.Resources;

import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;

class CipherMapBuilderTest {

  private static final Answer<String> ANSWER_BY_URL = new Answer<String>() {
    @Override
    public String answer(InvocationOnMock invocation) throws Throwable {
      String[] url = invocation.getArgument(0, String.class).split("/");
      return Resources.toString(Resources.getResource("builder/" + url[url.length - 1]),
          StandardCharsets.UTF_8);
    }
  };
  
  private Map<String, Map<String, String>> ciphermap = new TreeMap<String, Map<String,String>>();
  
  @BeforeEach
  void setUp() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    ciphermap = mapper.readValue(
        Resources.toString(Resources.getResource("ciphermap.json"), StandardCharsets.UTF_8),
        new TypeReference<Map<String, Map<String, String>>>() {
        });
  }

  @Test
  void testFallbackFetch() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL)))
          .thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL)))
          .thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenReturn(StringUtils.EMPTY);

      // fall back to local resource version if nothing can be fetched
      assertEquals(CipherMapBuilder.builder().fetch().build().keySet(),
          CipherMapBuilder.builder().build().keySet());
    }
  }

  @Test
  void testParseIana() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL)))
          .thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL)))
          .thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenReturn(StringUtils.EMPTY);

      CipherMapJson data = CipherMapBuilder.builder().fetch().build();

      assertEquals(ciphermap.size(), data.size());
      for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
        assertTrue(data.containsKey(entry.getKey()));
        assertEquals(entry.getValue().get("IANA"), data.get(entry.getKey()).getIana());
      }
    }
  }

}
