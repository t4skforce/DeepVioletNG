package io.github.t4skforce.deepviolet.json.mozilla;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.t4skforce.deepviolet.util.Downloader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;



class MozillaCertsIntegrationTest {

  private ObjectMapper objectMapper;

  @BeforeEach
  public void setUp() {
    objectMapper = new ObjectMapper();
    objectMapper.configure(MapperFeature.USE_ANNOTATIONS, true);
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  @Test
  void testMapping() throws Exception {
    assertNotNull(objectMapper);
    MozillaCerts certs = objectMapper.readValue(
        Downloader.get("https://ssl-config.mozilla.org/guidelines/latest.json"),
        MozillaCerts.class);
    assertEquals(3, certs.getConfigurations().size());
  }

}
