package io.github.t4skforce.deepviolet.json;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;

public class TLSVersion {
	private static final String TL_SV1 = "TLSv1";
	private static final String SS_LV3 = "SSLv3";
	private static final String SS_LV2 = "SSLv2";
	public static final int UNKNOWN = 0xFFFF;
	public static final int SSL_V2 = 0x0200;
	public static final int SSL_V3 = 0x0300;
	public static final int TLS_V1 = 0x0301;
	public static final int TLS_V1_1 = 0x0302;
	public static final int TLS_V1_2 = 0x0303;
	public static final int TLS_V1_3 = 0x0304;

	private static final Pattern TLS_REGEX = Pattern.compile("^TLSv1.([0-9])$", Pattern.CASE_INSENSITIVE);

	private static final Map<Integer, TLSVersion> VERSIONS = new HashMap<>();
	static {
		VERSIONS.put(UNKNOWN, of(UNKNOWN));
		VERSIONS.put(SSL_V2, of(SSL_V2));
		VERSIONS.put(SSL_V3, of(SSL_V3));
		VERSIONS.put(TLS_V1, of(TLS_V1));
		VERSIONS.put(TLS_V1_1, of(TLS_V1_1));
		VERSIONS.put(TLS_V1_2, of(TLS_V1_2));
		VERSIONS.put(TLS_V1_3, of(TLS_V1_3));
	}

	private Integer version;
	private String name;

	private TLSVersion(int version, String name) {
		this.version = version;
		this.name = name;
	}

	@JsonCreator
	public static TLSVersion of(String name) {
		if (name != null) {
			if (name.equalsIgnoreCase(SS_LV2)) {
				return of(SSL_V2);
			} else if (name.equalsIgnoreCase(SS_LV3)) {
				return of(SSL_V3);
			} else if (name.equalsIgnoreCase(TL_SV1)) {
				return of(TLS_V1);
			}
			Matcher tlsm = TLS_REGEX.matcher(name);
			if (tlsm.matches()) {
				return of(0x0301 + Integer.valueOf(tlsm.group(1)));
			}

		}
		return new TLSVersion(UNKNOWN, "UNKNOWN_NAME:" + name);
	}

	public static TLSVersion of(int version) {
		TLSVersion tv;
		if (VERSIONS.containsKey(version)) {
			return VERSIONS.get(version);
		}
		if (version == SSL_V2) {
			tv = new TLSVersion(version, SS_LV2);
		} else if (version == SSL_V3) {
			tv = new TLSVersion(version, SS_LV3);
		} else if (version >>> 8 == 0x03) {
			tv = new TLSVersion(version, "TLSv1." + ((version & 0xFF) - 1));
		} else {
			tv = new TLSVersion(version, String.format("UNKNOWN_VERSION:0x%04X", version));
		}
		VERSIONS.put(version, tv);
		return tv;
	}

	public Integer getVersion() {
		return version;
	}

	public String getName() {
		return name;
	}

	@Override
	public int hashCode() {
		return Objects.hash(version);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TLSVersion)) {
			return false;
		}
		TLSVersion other = (TLSVersion) obj;
		return Objects.equals(version, other.version);
	}

	@Override
	public String toString() {
		return name + " (" + String.format("0x%04X", version) + ")";
	}
}
