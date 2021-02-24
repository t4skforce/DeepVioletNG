package io.github.t4skforce.deepviolet.json.mozilla;

import static com.google.common.truth.Truth.assertThat;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.Resources;
import io.github.t4skforce.deepviolet.json.CompatibilityEnum;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;



class MozillaCertsTest {
  private ObjectMapper objectMapper;

  @BeforeEach
  public void setUp() {
    objectMapper = new ObjectMapper();
    objectMapper.configure(MapperFeature.USE_ANNOTATIONS, true);
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  @ParameterizedTest 
  @ValueSource(strings = { "4.0.json", "5.1.json", "5.2.json", "5.3.json", "5.4.json", "5.5.json", "5.6.json" })
  void testMapping(String resourceName) throws Exception {
    String json = Resources.toString(Resources.getResource("mozilla/guidelines/" + resourceName),
        StandardCharsets.UTF_8);
    MozillaCerts certs = objectMapper.readValue(json, MozillaCerts.class);

    assertThat(certs.getConfigurations().keySet()).containsExactly(CompatibilityEnum.MORDERN,
        CompatibilityEnum.INTERMEDIATE, CompatibilityEnum.OLD);

    MozillaConfig modern = certs.getConfigurations().get(CompatibilityEnum.MORDERN);
    assertThat(modern.getCiphersuites()).containsAnyOf("TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256");
    assertThat(modern.getCiphers()).containsKey("openssl");

    MozillaConfig internediate = certs.getConfigurations().get(CompatibilityEnum.INTERMEDIATE);
    assertThat(internediate.getCiphersuites()).containsAnyOf("TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256");
    assertThat(internediate.getCiphers()).containsKey("openssl");

    MozillaConfig old = certs.getConfigurations().get(CompatibilityEnum.OLD);
    assertThat(old.getCiphersuites()).containsAnyOf("TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256");
    assertThat(old.getCiphers()).containsKey("openssl");
  }
}
