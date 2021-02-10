package io.github.t4skforce.deepviolet.json.mozilla;

import java.net.URL;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.t4skforce.deepviolet.json.CompatibilityEnum;
import io.github.t4skforce.deepviolet.util.Downloader;

public class MozillaCerts {

    @JsonProperty("version")
    private Double version;

    @JsonProperty("href")
    private URL href;

    @JsonProperty("configurations")
    private Map<CompatibilityEnum, MozillaConfig> configurations;

    public Double getVersion() {
        return version;
    }

    public void setVersion(Double version) {
        this.version = version;
    }

    public URL getHref() {
        return href;
    }

    public void setHref(URL href) {
        this.href = href;
    }

    public Map<CompatibilityEnum, MozillaConfig> getConfigurations() {
        return configurations;
    }

    public void setConfigurations(Map<CompatibilityEnum, MozillaConfig> configurations) {
        this.configurations = configurations;
    }

    public static void main(String[] args) throws Exception {
        // https://wiki.mozilla.org/Security/Server_Side_TLS
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(MapperFeature.USE_ANNOTATIONS, true);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        MozillaCerts crts = mapper.readValue(Downloader.get("https://ssl-config.mozilla.org/guidelines/latest.json"),
                MozillaCerts.class);
        System.out.println(mapper.writeValueAsString(crts));
    }

}
