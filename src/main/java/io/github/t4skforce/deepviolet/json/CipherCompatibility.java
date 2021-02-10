package io.github.t4skforce.deepviolet.json;

import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CipherCompatibility {

    @JsonProperty("type")
    private CompatibilityEnum type;

    @JsonProperty("certificate_curves")
    private Set<String> certificateCurves = new TreeSet<>();

    @JsonProperty("certificate_signatures")
    private Set<String> certificateSignatures = new TreeSet<>();

    @JsonProperty("certificate_types")
    private Set<String> certificateTypes = new TreeSet<>();

    @JsonProperty("dh_param_size")
    private Integer dhParamSize;

    @JsonProperty("ecdh_param_size")
    private Integer ecdhParamSize;

    @JsonProperty("hsts_min_age")
    private Long hstsMinAge;

    @JsonProperty("maximum_certificate_lifespan")
    private Long maximumCertificateLifespan;

    @JsonProperty("ocsp_staple")
    private Boolean ocspStaple;

    @JsonProperty("oldest_clients")
    private Set<String> oldestClients = new TreeSet<>();

    @JsonProperty("recommended_certificate_lifespan")
    private Long recommendedCertificateLifespan;

    @JsonProperty("rsa_key_size")
    private Long rsaKeySize;

    @JsonProperty("server_preferred_order")
    private Boolean serverPeferredOrder;

    @JsonProperty("tls_curves")
    private Set<String> tlsCurves = new TreeSet<>();

    @JsonProperty("tls_versions")
    private Set<String> tlsVersions = new TreeSet<>();

    public CompatibilityEnum getType() {
        return type;
    }

    public void setType(CompatibilityEnum type) {
        this.type = type;
    }

    public Set<String> getCertificateCurves() {
        return certificateCurves;
    }

    public void setCertificateCurves(Set<String> certificateCurves) {
        this.certificateCurves = certificateCurves;
    }

    public Set<String> getCertificateSignatures() {
        return certificateSignatures;
    }

    public void setCertificateSignatures(Set<String> certificateSignatures) {
        this.certificateSignatures = certificateSignatures;
    }

    public Set<String> getCertificateTypes() {
        return certificateTypes;
    }

    public void setCertificateTypes(Set<String> certificateTypes) {
        this.certificateTypes = certificateTypes;
    }

    public Integer getDhParamSize() {
        return dhParamSize;
    }

    public void setDhParamSize(Integer dhParamSize) {
        this.dhParamSize = dhParamSize;
    }

    public Integer getEcdhParamSize() {
        return ecdhParamSize;
    }

    public void setEcdhParamSize(Integer ecdhParamSize) {
        this.ecdhParamSize = ecdhParamSize;
    }

    public Long getHstsMinAge() {
        return hstsMinAge;
    }

    public void setHstsMinAge(Long hstsMinAge) {
        this.hstsMinAge = hstsMinAge;
    }

    public Long getMaximumCertificateLifespan() {
        return maximumCertificateLifespan;
    }

    public void setMaximumCertificateLifespan(Long maximumCertificateLifespan) {
        this.maximumCertificateLifespan = maximumCertificateLifespan;
    }

    public Boolean getOcspStaple() {
        return ocspStaple;
    }

    public void setOcspStaple(Boolean ocspStaple) {
        this.ocspStaple = ocspStaple;
    }

    public Set<String> getOldestClients() {
        return oldestClients;
    }

    public void setOldestClients(Set<String> oldestClients) {
        this.oldestClients = oldestClients;
    }

    public Long getRecommendedCertificateLifespan() {
        return recommendedCertificateLifespan;
    }

    public void setRecommendedCertificateLifespan(Long recommendedCertificateLifespan) {
        this.recommendedCertificateLifespan = recommendedCertificateLifespan;
    }

    public Long getRsaKeySize() {
        return rsaKeySize;
    }

    public void setRsaKeySize(Long rsaKeySize) {
        this.rsaKeySize = rsaKeySize;
    }

    public Boolean getServerPeferredOrder() {
        return serverPeferredOrder;
    }

    public void setServerPeferredOrder(Boolean serverPeferredOrder) {
        this.serverPeferredOrder = serverPeferredOrder;
    }

    public Set<String> getTlsCurves() {
        return tlsCurves;
    }

    public void setTlsCurves(Set<String> tlsCurves) {
        this.tlsCurves = tlsCurves;
    }

    public Set<String> getTlsVersions() {
        return tlsVersions;
    }

    public void setTlsVersions(Set<String> tlsVersions) {
        this.tlsVersions = tlsVersions;
    }

}
