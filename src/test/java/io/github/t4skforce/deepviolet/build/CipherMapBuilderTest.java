package io.github.t4skforce.deepviolet.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.hash.Hashing;
import com.google.common.io.Resources;

import io.github.t4skforce.deepviolet.build.CipherMapBuilder.MessageConsumer;
import io.github.t4skforce.deepviolet.json.CipherMapJson;
import io.github.t4skforce.deepviolet.util.Downloader;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

class CipherMapBuilderTest {

  private static final Answer<String> ANSWER_BY_URL = new Answer<String>() {
    @Override
    public String answer(InvocationOnMock invocation) throws Throwable {
      String[] url = invocation.getArgument(0, String.class).split("/");
      return Resources.toString(Resources.getResource("builder/download/" + url[url.length - 1]),
          StandardCharsets.UTF_8);
    }
  };

  private Map<String, Map<String, String>> ciphermap = new TreeMap<String, Map<String, String>>();

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
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL)))
          .thenReturn(StringUtils.EMPTY);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL)))
          .thenReturn(StringUtils.EMPTY);

      // fall back to local resource version if nothing can be fetched
      assertEquals(CipherMapBuilder.builder().fetch().build().keySet(),
          CipherMapBuilder.builder().build().keySet());
    }
  }

  @Test
  void testParseIana() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);

      CipherMapJson data = CipherMapBuilder.builder().fetchIana().build();

      assertEquals(ciphermap.size(), data.size());
      for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
        assertTrue(data.containsKey(entry.getKey()));
        assertEquals(entry.getValue().get("IANA"), data.get(entry.getKey()).getIana());
      }
    }
  }

  @Test
  void testParseNss() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenAnswer(ANSWER_BY_URL);

      CipherMapJson data = CipherMapBuilder.builder().fetchIana().fetchNss().build();

      assertEquals(ciphermap.size(), data.size());
      for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
        assertTrue(data.containsKey(entry.getKey()));
        assertEquals(entry.getValue().get("NSS"), data.get(entry.getKey()).getNss());
      }
    }
  }

  @Test
  void testParseOpenSsl() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL))).thenAnswer(ANSWER_BY_URL);

      CipherMapJson data = CipherMapBuilder.builder().fetchIana().fetchOpenSsl().build();

      assertEquals(ciphermap.size(), data.size());
      for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
        assertTrue(data.containsKey(entry.getKey()));
        assertEquals(entry.getValue().get("OpenSSL"), data.get(entry.getKey()).getOpenssl());
      }
    }
  }

  @Test
  void testParseGnuTls() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL))).thenAnswer(ANSWER_BY_URL);

      CipherMapJson data = CipherMapBuilder.builder().fetchIana().fetchGnuTls().build();

      assertEquals(ciphermap.size(), data.size());
      for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
        assertTrue(data.containsKey(entry.getKey()));
        assertEquals(entry.getValue().get("GnuTLS"), data.get(entry.getKey()).getGnutls());
      }
    }
  }

  @Test
  void testParsAll() throws Exception {
    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL))).thenAnswer(ANSWER_BY_URL);

      CipherMapJson data = CipherMapBuilder.builder().fetch().build();

      assertEquals(ciphermap.size(), data.size());
      for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
        assertTrue(data.containsKey(entry.getKey()));
        assertEquals(entry.getValue().get("IANA"), data.get(entry.getKey()).getIana());
        assertEquals(entry.getValue().get("NSS"), data.get(entry.getKey()).getNss());
        assertEquals(entry.getValue().get("OpenSSL"), data.get(entry.getKey()).getOpenssl());
        assertEquals(entry.getValue().get("GnuTLS"), data.get(entry.getKey()).getGnutls());
      }
    }
  }

  @Test
  void testBuildFile() throws Exception {
    File source = new File(Resources.getResource("ciphermap.json").getFile());
    CipherMapJson data = CipherMapBuilder.builder().build(source);
    assertEquals(ciphermap.size(), data.size());
    for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
      assertTrue(data.containsKey(entry.getKey()));
      assertEquals(entry.getValue().get("IANA"), data.get(entry.getKey()).getIana());
      assertEquals(entry.getValue().get("NSS"), data.get(entry.getKey()).getNss());
      assertEquals(entry.getValue().get("OpenSSL"), data.get(entry.getKey()).getOpenssl());
      assertEquals(entry.getValue().get("GnuTLS"), data.get(entry.getKey()).getGnutls());
    }
  }

  @Test
  void testBuildResource() throws Exception {
    CipherMapJson data = CipherMapBuilder.builder().build("ciphermap.json");
    assertEquals(ciphermap.size(), data.size());
    for (Entry<String, Map<String, String>> entry : ciphermap.entrySet()) {
      assertTrue(data.containsKey(entry.getKey()));
      assertEquals(entry.getValue().get("IANA"), data.get(entry.getKey()).getIana());
      assertEquals(entry.getValue().get("NSS"), data.get(entry.getKey()).getNss());
      assertEquals(entry.getValue().get("OpenSSL"), data.get(entry.getKey()).getOpenssl());
      assertEquals(entry.getValue().get("GnuTLS"), data.get(entry.getKey()).getGnutls());
    }
  }

  @Test
  void testWrite(@TempDir Path tempDir) throws Exception {
    Path ciphermapOut = tempDir.resolve("ciphermap.json.out");

    CipherMapBuilder.builder().load("ciphermap.json").write(ciphermapOut.toFile());

    String output = new String(Files.readAllBytes(ciphermapOut), StandardCharsets.UTF_8);
    String input = Resources.toString(Resources.getResource("ciphermap.json"),
        StandardCharsets.UTF_8);

    assertEquals(Hashing.sha256().hashString(input, StandardCharsets.UTF_8).toString(),
        Hashing.sha256().hashString(output, StandardCharsets.UTF_8).toString());
  }

  private class MessageTester implements MessageConsumer<String, Object[]> {
    @Override
    public void accept(String key, Object[] params) {
      // ignore
    }
  }

  @Test
  void testLogging() throws Exception {

    try (MockedStatic<Downloader> mock = mockStatic(Downloader.class)) {
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.IANA_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.NSS_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.OPENSSL_URL))).thenAnswer(ANSWER_BY_URL);
      mock.when(() -> Downloader.get(eq(CipherMapBuilder.GNUTLS_URL))).thenAnswer(ANSWER_BY_URL);

      MessageTester log = mock(MessageTester.class);
      MessageTester warn = mock(MessageTester.class);

      CipherMapBuilder.builder().log(log).warn(warn).fetch().build();

      verify(log, times(4)).accept(eq("cypher.builder.info.fetching"), any(Object[].class));
      verify(log, times(4)).accept(eq("cypher.builder.info.found"), any(Object[].class));
      verify(warn, times(6)).accept(eq("cypher.builder.warn.not.iana"), any(Object[].class));
    }

  }

  @Test
  void testFormat() throws Exception {
    assertEquals("found 123 entries",
        CipherMapBuilder.format("cypher.builder.info.found", new Object[] { 123 }));
  }

}
