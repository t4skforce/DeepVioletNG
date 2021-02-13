package io.github.t4skforce.deepviolet.json.mozilla;

import java.net.URL;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import io.github.t4skforce.deepviolet.json.CompatibilityEnum;

public class MozillaCerts {

	private Double version;

	private URL href;

	private Map<CompatibilityEnum, MozillaConfig> configurations;

	@JsonCreator
	public MozillaCerts(@JsonProperty("version") final Double version, @JsonProperty("href") final URL href,
			@JsonProperty("configurations") final Map<CompatibilityEnum, MozillaConfig> configurations) {
		this.version = version;
		this.href = href;
		this.configurations = configurations;
	}

	public Double getVersion() {
		return version;
	}

	public URL getHref() {
		return href;
	}

	public Map<CompatibilityEnum, MozillaConfig> getConfigurations() {
		return configurations;
	}

}
