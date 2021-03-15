package io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeName;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@JacksonAnnotationsInside
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder(value = { "type", "length", "legacy_version", "random", "sessionId", "cipherSuites", "commpressionMethod", "extensions" })
@JsonTypeName(TlsHandshake.Name.CLIENT_HELLO)
public @interface TlsClientHello {

  public abstract class Fields {
    public static final String LEGACY_VERSION = "legacy_version";
    public static final String RANDOM = "random";
    public static final String SESSIONID = "sessionId";
    public static final String CIPHER_SUITES = "cipherSuites";
    public static final String COMPRESSION_METHOD = "commpressionMethod";
    public static final String EXTENSIONS = "extensions";
  }

}
