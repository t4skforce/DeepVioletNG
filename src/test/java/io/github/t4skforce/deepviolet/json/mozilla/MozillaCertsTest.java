package io.github.t4skforce.deepviolet.json.mozilla;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.t4skforce.deepviolet.util.Downloader;

public class MozillaCertsTest {

	private ObjectMapper objectMapper;

	@BeforeEach
	public void setUp() {
		objectMapper = new ObjectMapper();
		objectMapper.configure(MapperFeature.USE_ANNOTATIONS, true);
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	@Test
	public void testLucky() throws Exception {
		MozillaCerts certs = objectMapper
				.readValue(Downloader.get("https://ssl-config.mozilla.org/guidelines/latest.json"), MozillaCerts.class);
		assertEquals(certs.getConfigurations().size(), 3);
	}

}
