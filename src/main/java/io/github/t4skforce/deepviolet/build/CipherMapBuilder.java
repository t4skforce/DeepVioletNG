package io.github.t4skforce.deepviolet.build;

import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.common.io.Resources;
import io.github.t4skforce.deepviolet.json.CipherMapClassificationsJson;
import io.github.t4skforce.deepviolet.json.CipherMapJson;
import io.github.t4skforce.deepviolet.util.Downloader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * Reimplementation of https://github.com/april/tls-table/blob/master/tls-table.py in Java
 *
 * @author t4skforce
 *
 */
public class CipherMapBuilder {

  private static final String IANA_URL = "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml";
  private static final String NSS_URL = "https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ssl/sslproto.h";
  private static final String OPENSSL_URL = "https://raw.githubusercontent.com/openssl/openssl/master/include/openssl/tls1.h";
  private static final String GNUTLS_URL = "https://gitlab.com/gnutls/gnutls/raw/master/lib/algorithms/ciphersuites.c";

  private static final String BASE_KEY = "cypher.builder";
  private static final String CIPHERMAP_JSON = "ciphermap.json";

  private static final Pattern REGEX_IANA = Pattern.compile(
      "<td[^>]*>(?<hex>0x[0-9|A-F]{2},0x[0-9|A-F]{2})</td[^>]*>[^<]*<td[^>]*>(?<name>TLS_[^\\s]+)</td[^>]*>",
      Pattern.DOTALL | Pattern.MULTILINE);

  private static final Pattern REGEX_NSS = Pattern.compile(
      "#\\s*define\\s+(?<name>TLS_[^\\s]+)\\s+(?<hex>0x[A-F|0-9]{4})",
      Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private static final Pattern REGEX_OPENSSL = Pattern.compile(
      "#\\s*define\\s+TLS1_CK_(?<name>[^\\s]+)\\s+(?<hex>0x[A-F|0-9]{8})",
      Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private static final Pattern REGEX_OPENSSL_NAMES = Pattern.compile(
      "#\\s*define\\s+TLS1_TXT_(?<key>[^\\s]+)\\s+\"(?<value>[^\"]+)\"",
      Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private static final Pattern REGEX_GNUTLS_NAMES = Pattern.compile(
      "#\\s*define\\s*GNU(?<name>TLS_[^\\s]+)\\s*\\{\\s*(?<hex1>0x[A-F|0-9]{2})\\s*,\\s*(?<hex2>0x[A-F|0-9]{2})\\s*\\}",
      Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private CipherMapJson cipherMapJson = new CipherMapJson();

  private Map<String, String> ianaNameMap = new HashMap<>();

  private MessageConsumer<String, Object[]> logConsumer = (m, o) -> {
  };

  private MessageConsumer<String, Object[]> warnConsumer = (m, o) -> {
  };

  private ObjectMapper mapper;

  private static final ResourceBundle RES_BUNDLE = ResourceBundle.getBundle("Messages");

  private CipherMapBuilder() {
    mapper = new ObjectMapper();
    mapper.configure(MapperFeature.USE_ANNOTATIONS, true);
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static CipherMapBuilder builder() {
    return new CipherMapBuilder();
  }

  public CipherMapBuilder build() throws Exception {
    parseIana();
    parseNss();
    parseOpenSsl();
    parseGnuTls();
    return this;
  }

  public CipherMapBuilder write(File target) throws IOException {
    ObjectMapper mapper = new ObjectMapper();
    mapper.configure(MapperFeature.USE_ANNOTATIONS, true);
    ObjectWriter writer = mapper.writer(new DefaultPrettyPrinter());
    writer.writeValue(target, cipherMapJson);
    return this;
  }

  public CipherMapJson get() throws IOException {
    if (MapUtils.isEmpty(cipherMapJson)) {
      cipherMapJson = get(CIPHERMAP_JSON);
    }
    return cipherMapJson;
  }

  public CipherMapJson get(File file) throws IOException {
    cipherMapJson = mapper.readValue(file, CipherMapJson.class);
    return cipherMapJson;
  }

  public CipherMapJson get(String resourceName) throws IOException {
    String json = Resources.toString(Resources.getResource(resourceName), StandardCharsets.UTF_8);
    cipherMapJson = mapper.readValue(json, CipherMapJson.class);
    return cipherMapJson;
  }

  public CipherMapBuilder log(MessageConsumer<String, Object[]> logConsumer) {
    this.logConsumer = logConsumer;
    return this;
  }

  private void log(String key, Object... params) {
    this.logConsumer.accept(StringUtils.joinWith(".", BASE_KEY, key), params);
  }

  public CipherMapBuilder warn(MessageConsumer<String, Object[]> warnConsumer) {
    this.warnConsumer = warnConsumer;
    return this;
  }

  private void warn(String key, Object... params) {
    this.warnConsumer.accept(StringUtils.joinWith(".", BASE_KEY, key), params);
  }

  private int parseIana() throws IOException {
    int cnt = 0;
    log("info.fetching", "IANA", IANA_URL);
    Matcher sources = REGEX_IANA.matcher(Downloader.get(IANA_URL));
    while (sources.find()) {
      String hex = sources.group("hex").trim().toUpperCase().replaceAll("X", "x");
      String name = sources.group("name").trim().toUpperCase();

      if (!cipherMapJson.containsKey(hex)) {
        cipherMapJson.put(hex, new CipherMapClassificationsJson());
      }
      CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
      cipher.setIana(name);

      cipherMapJson.put(hex, cipher);
      ianaNameMap.put(name, hex);
      cnt++;
    }
    log("info.found", cnt);
    return cnt;
  }

  private int parseNss() throws IOException {
    int cnt = 0;
    log("info.fetching", "NSS", NSS_URL);
    Matcher sources = REGEX_NSS.matcher(Downloader.get(NSS_URL));
    while (sources.find()) {
      String hex = sources.group("hex").trim().toUpperCase().replaceAll("X", "x");
      hex = String.format("%s,0x%s", hex.substring(0, 4), hex.substring(4, 6));
      String name = sources.group("name").trim().toUpperCase();
      if (!cipherMapJson.containsKey(hex)) {
        warn("warn.not.iana", "NSS", hex, name);
        continue;
      }
      CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
      cipher.setNss(name);

      cnt++;
    }
    log("info.found", cnt);
    return cnt;
  }

  private int parseOpenSsl() throws IOException {
    int cnt = 0;
    log("info.fetching", "OpenSSL", NSS_URL);
    String content = Downloader.get(OPENSSL_URL);

    // mapping e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 ->
    // ECDHE-RSA-AES128-GCM-SHA256
    Map<String, String> mapping = new HashMap<>();
    Matcher sources = REGEX_OPENSSL_NAMES.matcher(content);
    while (sources.find()) {
      String key = sources.group("key").trim().toUpperCase();
      String value = sources.group("value").trim().toUpperCase();
      mapping.put(key, value);
    }

    sources = REGEX_OPENSSL.matcher(content);
    while (sources.find()) {
      String name = sources.group("name").trim().toUpperCase();
      name = mapping.get(name);
      String hex = sources.group("hex").trim().toUpperCase().replaceAll("X", "x");
      hex = String.format("0x%s,0x%s", hex.substring(6, 8), hex.substring(8, 10));

      if (!cipherMapJson.containsKey(hex)) {
        warn("warn.not.iana", "NSS", hex, name);
        continue;
      }
      CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
      cipher.setOpenssl(name);
      cnt++;
    }
    log("info.found", cnt);
    return cnt;
  }

  private int parseGnuTls() throws IOException {
    int cnt = 0;
    log("info.fetching", "GnuTLS", NSS_URL);
    Matcher sources = REGEX_GNUTLS_NAMES.matcher(Downloader.get(GNUTLS_URL));
    while (sources.find()) {
      String hex = String.format("%s,%s",
          sources.group("hex1").trim().toUpperCase().replaceAll("X", "x"),
          sources.group("hex2").trim().toUpperCase().replaceAll("X", "x"));
      String name = sources.group("name").trim().toUpperCase();
      if (!cipherMapJson.containsKey(hex)) {
        warn("warn.not.iana", "NSS", hex, name);
        continue;
      }
      CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
      cipher.setGnutls(name);
      cnt++;
    }
    log("info.found", cnt);
    return cnt;
  }

  private static String format(String key, Object[] params) {
    return MessageFormat.format(RES_BUNDLE.getString(key).replaceAll("'", "''"), params);
  }

  @FunctionalInterface
  public interface MessageConsumer<T, U> {
    public void accept(T key, U params);
  }

  @SuppressWarnings("all")
  public static void main(String[] args) throws Exception {
    CipherMapBuilder.builder().log((key, params) -> {
      System.out.println("[INFO] " + format(key, params));
    }).warn((key, params) -> {
      System.out.println("[WARNING] " + format(key, params));
    }).build().write(Paths.get(args[0], CIPHERMAP_JSON).toFile());
  }
}
