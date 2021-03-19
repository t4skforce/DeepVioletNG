package io.github.t4skforce.deepviolet.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CipherMapClassificationsJson {

  @JsonProperty("GnuTLS")
  private String gnutls;

  @JsonProperty("NSS")
  private String nss;

  @JsonProperty("IANA")
  private String iana;

  @JsonProperty("OpenSSL")
  private String openssl;

  @JsonProperty("compatibility")
  private CipherCompatibility compatibility;

  public String getGnutls() {
    return gnutls;
  }

  public void setGnutls(String gnutls) {
    this.gnutls = gnutls;
  }

  public String getNss() {
    return nss;
  }

  public void setNss(String nss) {
    this.nss = nss;
  }

  public String getIana() {
    return iana;
  }

  public void setIana(String iana) {
    this.iana = iana;
  }

  public String getOpenssl() {
    return openssl;
  }

  public void setOpenssl(String openssl) {
    this.openssl = openssl;
  }
}
