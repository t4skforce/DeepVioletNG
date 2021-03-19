package io.github.t4skforce.deepviolet.json;

import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.common.io.Resources;

import io.github.t4skforce.deepviolet.util.Downloader;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;

public class CipherMap extends ConcurrentHashMap<String, CipherMapClassificationsJson> {
  private static final long serialVersionUID = 5660722767135755938L;

  private static CipherMap instance;

  public CipherMap() {
    super();
  }

  public CipherMap(String hexName, CipherMapClassificationsJson clazz) {
    put(hexName, clazz);
  }

  public static synchronized CipherMap getInstance() throws IOException {
    if (CipherMap.instance == null) {
      CipherMap.instance = builder().load().build();
    }
    return CipherMap.instance;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private static final String BASE_KEY = "cypher.builder";
    private static final String MSG_WARN_NOT_IANA = "warn.not.iana";
    private static final String MSG_INFO_FOUND = "info.found";
    private static final String MSG_INFO_FETCHING = "info.fetching";

    private static final String CIPHERMAP_JSON = "ciphermap.json";

    protected static final String IANA_URL = "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml";
    protected static final String NSS_URL = "https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ssl/sslproto.h";
    protected static final String OPENSSL_URL = "https://raw.githubusercontent.com/openssl/openssl/master/include/openssl/tls1.h";
    protected static final String GNUTLS_URL = "https://gitlab.com/gnutls/gnutls/raw/master/lib/algorithms/ciphersuites.c";

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

    private CipherMap cipherMapJson = new CipherMap();

    private Map<String, String> ianaNameMap = new HashMap<>();

    private MessageConsumer<String, Object[]> logConsumer = (m, o) -> {
    };

    private MessageConsumer<String, Object[]> warnConsumer = (m, o) -> {
    };

    private ObjectMapper mapper;

    private static final ResourceBundle RES_BUNDLE = ResourceBundle.getBundle("Messages");

    private Builder() {
      mapper = new ObjectMapper();
      mapper.configure(MapperFeature.USE_ANNOTATIONS, true);
      mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public Builder write(File target) throws IOException {
      ObjectWriter writer = mapper.writer(new DefaultPrettyPrinter());
      writer.writeValue(target, cipherMapJson);
      return this;
    }

    public Builder load() throws IOException {
      if (MapUtils.isEmpty(cipherMapJson)) {
        load(CIPHERMAP_JSON);
      }
      return this;
    }

    public Builder load(File file) throws IOException {
      cipherMapJson = mapper.readValue(file, CipherMap.class);
      return this;
    }

    public Builder load(String resourceName) throws IOException {
      String json = Resources.toString(Resources.getResource(resourceName), StandardCharsets.UTF_8);
      cipherMapJson = mapper.readValue(json, CipherMap.class);
      return this;
    }

    public CipherMap build() throws IOException {
      load();
      return cipherMapJson;
    }

    public Builder log(MessageConsumer<String, Object[]> logConsumer) {
      this.logConsumer = logConsumer;
      return this;
    }

    private void log(String key, Object... params) {
      this.logConsumer.accept(StringUtils.joinWith(".", BASE_KEY, key), params);
    }

    public Builder warn(MessageConsumer<String, Object[]> warnConsumer) {
      this.warnConsumer = warnConsumer;
      return this;
    }

    private void warn(String key, Object... params) {
      this.warnConsumer.accept(StringUtils.joinWith(".", BASE_KEY, key), params);
    }

    public Builder fetch() throws IOException {
      return fetchIana().fetchNss().fetchOpenSsl().fetchGnuTls();
    }

    public Builder fetchIana() throws IOException {
      int cnt = 0;
      log(MSG_INFO_FETCHING, "IANA", IANA_URL);
      Matcher sources = REGEX_IANA.matcher(Downloader.get(IANA_URL));
      while (sources.find()) {
        String hex = sources.group("hex").trim().toUpperCase().replace("X", "x");
        String name = sources.group("name").trim().toUpperCase();

        cipherMapJson.computeIfAbsent(hex, k -> new CipherMapClassificationsJson());

        CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
        cipher.setIana(name);

        cipherMapJson.put(hex, cipher);
        ianaNameMap.put(name, hex);
        cnt++;
      }
      log(MSG_INFO_FOUND, cnt);
      return this;
    }

    public Builder fetchNss() throws IOException {
      int cnt = 0;
      log(MSG_INFO_FETCHING, "NSS", NSS_URL);
      Matcher sources = REGEX_NSS.matcher(Downloader.get(NSS_URL));
      while (sources.find()) {
        String hex = sources.group("hex").trim().toUpperCase().replace("X", "x");
        hex = String.format("%s,0x%s", hex.substring(0, 4), hex.substring(4, 6));
        String name = sources.group("name").trim().toUpperCase();
        if (!cipherMapJson.containsKey(hex)) {
          warn(MSG_WARN_NOT_IANA, "NSS", hex, name);
          continue;
        }
        CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
        cipher.setNss(name);

        cnt++;
      }
      log(MSG_INFO_FOUND, cnt);
      return this;
    }

    public Builder fetchOpenSsl() throws IOException {
      int cnt = 0;
      log(MSG_INFO_FETCHING, "OpenSSL", NSS_URL);
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
        String hex = sources.group("hex").trim().toUpperCase().replace("X", "x");
        hex = String.format("0x%s,0x%s", hex.substring(6, 8), hex.substring(8, 10));

        if (!cipherMapJson.containsKey(hex)) {
          warn(MSG_WARN_NOT_IANA, "OpenSSL", hex, name);
          continue;
        }
        CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
        cipher.setOpenssl(name);
        cnt++;
      }
      log(MSG_INFO_FOUND, cnt);
      return this;
    }

    public Builder fetchGnuTls() throws IOException {
      int cnt = 0;
      log(MSG_INFO_FETCHING, "GnuTLS", NSS_URL);
      Matcher sources = REGEX_GNUTLS_NAMES.matcher(Downloader.get(GNUTLS_URL));
      while (sources.find()) {
        String hex = String.format("%s,%s",
            sources.group("hex1").trim().toUpperCase().replace("X", "x"),
            sources.group("hex2").trim().toUpperCase().replace("X", "x"));
        String name = sources.group("name").trim().toUpperCase();
        if (!cipherMapJson.containsKey(hex)) {
          warn(MSG_WARN_NOT_IANA, "GnuTLS", hex, name);
          continue;
        }
        CipherMapClassificationsJson cipher = cipherMapJson.get(hex);
        cipher.setGnutls(name);
        cnt++;
      }
      log(MSG_INFO_FOUND, cnt);
      return this;
    }

    @FunctionalInterface
    public interface MessageConsumer<T, U> {
      public void accept(T key, U params);
    }

    public static String format(String key, Object[] params) {
      return MessageFormat.format(RES_BUNDLE.getString(key).replace("'", "''"), params);
    }
  }

  public CipherMapClassificationsJson get(byte[] c) {
    return get(c[0], c[1]);
  }

  public CipherMapClassificationsJson get(byte c1, byte c2) {
    return get(String.format("0x%02X", c1) + "," + String.format("0x%02X", c2));
  }

  public boolean containsKey(byte[] c) {
    return containsKey(c[0], c[1]);
  }

  public boolean containsKey(byte c1, byte c2) {
    return containsKey(String.format("0x%02X", c1) + "," + String.format("0x%02X", c2));
  }

  @SuppressWarnings("all")
  public static void main(String[] args) throws Exception {
    CipherMap.builder().log((key, params) -> {
      System.out.println("[INFO] " + Builder.format(key, params));
    }).warn((key, params) -> {
      System.out.println("[WARNING] " + Builder.format(key, params));
    }).fetch().write(Paths.get(args[0], Builder.CIPHERMAP_JSON).toFile());
  }

}
