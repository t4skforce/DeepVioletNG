package io.github.t4skforce.deepviolet.protocol.tls.extension;

import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.util.HashMap;
import java.util.Map;

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
// https://tools.ietf.org/html/rfc6066
public class TlsExtensionType {
  private static final String RESERVED_FOR_PRIVATE_USE = "reserved_for_private_use";

  private static final String UNASSIGNED = "unassigned";

  private static final String RESERVED = "reserved";

  public static final TlsExtensionType SERVER_NAME = new TlsExtensionType(0, "server_name", true);
  public static final TlsExtensionType MAX_FRAGMENT_LENGTH = new TlsExtensionType(1,
      "max_fragment_length", false);
  public static final TlsExtensionType CLIENT_CERTIFICATE_URL = new TlsExtensionType(2,
      "client_certificate_url", true);
  public static final TlsExtensionType TRUSTED_CA_KEYS = new TlsExtensionType(3, "trusted_ca_keys",
      true);
  public static final TlsExtensionType TRUNCATED_HMAC = new TlsExtensionType(4, "truncated_hmac",
      false);
  public static final TlsExtensionType STATUS_REQUEST = new TlsExtensionType(5, "status_request",
      true);
  public static final TlsExtensionType USER_MAPPING = new TlsExtensionType(6, "user_mapping", true);
  public static final TlsExtensionType CLIENT_AUTHZ = new TlsExtensionType(7, "client_authz",
      false);
  public static final TlsExtensionType SERVER_AUTHZ = new TlsExtensionType(8, "server_authz",
      false);
  public static final TlsExtensionType CERT_TYPE = new TlsExtensionType(9, "cert_type", false);
  public static final TlsExtensionType SUPPORTED_GROUPS = new TlsExtensionType(10,
      "supported_groups", true);
  public static final TlsExtensionType EC_POINT_FORMATS = new TlsExtensionType(11,
      "ec_point_formats", true);
  public static final TlsExtensionType SRP = new TlsExtensionType(12, "srp", false);
  public static final TlsExtensionType SIGNATURE_ALGORITHMS = new TlsExtensionType(13,
      "signature_algorithms", true);
  public static final TlsExtensionType USE_SRTP = new TlsExtensionType(14, "use_srtp", true);
  public static final TlsExtensionType HEARTBEAT = new TlsExtensionType(15, "heartbeat", true);
  public static final TlsExtensionType APPLICATION_LAYER_PROTOCOL_NEGOTIATION = new TlsExtensionType(
      16, "application_layer_protocol_negotiation", true);
  public static final TlsExtensionType STATUS_REQUEST_V2 = new TlsExtensionType(17,
      "status_request_v2", true);
  public static final TlsExtensionType SIGNED_CERTIFICATE_TIMESTAMP = new TlsExtensionType(18,
      "signed_certificate_timestamp", false);
  public static final TlsExtensionType CLIENT_CERTIFICATE_TYPE = new TlsExtensionType(19,
      "client_certificate_type", true);
  public static final TlsExtensionType SERVER_CERTIFICATE_TYPE = new TlsExtensionType(20,
      "server_certificate_type", true);
  public static final TlsExtensionType PADDING = new TlsExtensionType(21, "padding", true);
  public static final TlsExtensionType ENCRYPT_THEN_MAC = new TlsExtensionType(22,
      "encrypt_then_mac", true);
  public static final TlsExtensionType EXTENDED_MASTER_SECRET = new TlsExtensionType(23,
      "extended_master_secret", true);
  public static final TlsExtensionType TOKEN_BINDING = new TlsExtensionType(24, "token_binding",
      true);
  public static final TlsExtensionType CACHED_INFO = new TlsExtensionType(25, "cached_info", true);
  public static final TlsExtensionType TLS_LTS = new TlsExtensionType(26, "tls_lts", false);
  public static final TlsExtensionType COMPRESS_CERTIFICATE = new TlsExtensionType(27,
      "compress_certificate", true);
  public static final TlsExtensionType RECORD_SIZE_LIMIT = new TlsExtensionType(28,
      "record_size_limit", true);
  public static final TlsExtensionType PWD_PROTECT = new TlsExtensionType(29, "pwd_protect", false);
  public static final TlsExtensionType PWD_CLEAR = new TlsExtensionType(30, "pwd_clear", false);
  public static final TlsExtensionType PASSWORD_SALT = new TlsExtensionType(31, "password_salt",
      false);
  public static final TlsExtensionType TICKET_PINNING = new TlsExtensionType(32, "ticket_pinning",
      false);
  public static final TlsExtensionType TLS_CERT_WITH_EXTERN_PSK = new TlsExtensionType(33,
      "tls_cert_with_extern_psk", false);
  public static final TlsExtensionType DELEGATED_CREDENTIALS = new TlsExtensionType(34,
      "delegated_credentials", false);
  public static final TlsExtensionType SESSION_TICKET = new TlsExtensionType(35, "session_ticket",
      true);
  public static final TlsExtensionType TLMSP = new TlsExtensionType(36, "TLMSP", false);
  public static final TlsExtensionType TLMSP_PROXYING = new TlsExtensionType(37, "TLMSP_proxying",
      false);
  public static final TlsExtensionType TLMSP_DELEGATE = new TlsExtensionType(38, "TLMSP_delegate",
      false);
  public static final TlsExtensionType SUPPORTED_EKT_CIPHERS = new TlsExtensionType(39,
      "supported_ekt_ciphers", true);
  public static final TlsExtensionType PRE_SHARED_KEY = new TlsExtensionType(41, "pre_shared_key",
      true);
  public static final TlsExtensionType EARLY_DATA = new TlsExtensionType(42, "early_data", true);
  public static final TlsExtensionType SUPPORTED_VERSIONS = new TlsExtensionType(43,
      "supported_versions", true);
  public static final TlsExtensionType COOKIE = new TlsExtensionType(44, "cookie", true);
  public static final TlsExtensionType PSK_KEY_EXCHANGE_MODES = new TlsExtensionType(45,
      "psk_key_exchange_modes", true);
  public static final TlsExtensionType CERTIFICATE_AUTHORITIES = new TlsExtensionType(47,
      "certificate_authorities", true);
  public static final TlsExtensionType OID_FILTERS = new TlsExtensionType(48, "oid_filters", true);
  public static final TlsExtensionType POST_HANDSHAKE_AUTH = new TlsExtensionType(49,
      "post_handshake_auth", true);
  public static final TlsExtensionType SIGNATURE_ALGORITHMS_CERT = new TlsExtensionType(50,
      "signature_algorithms_cert", true);
  public static final TlsExtensionType KEY_SHARE = new TlsExtensionType(51, "key_share", true);
  public static final TlsExtensionType TRANSPARENCY_INFO = new TlsExtensionType(52,
      "transparency_info", false);
  public static final TlsExtensionType CONNECTION_ID = new TlsExtensionType(53, "connection_id",
      false);
  public static final TlsExtensionType EXTERNAL_ID_HASH = new TlsExtensionType(55,
      "external_id_hash", true);
  public static final TlsExtensionType EXTERNAL_SESSION_ID = new TlsExtensionType(56,
      "external_session_id", true);
  public static final TlsExtensionType QUIC_TRANSPORT_PARAMETERS = new TlsExtensionType(57,
      "quic_transport_parameters", true);
  public static final TlsExtensionType TICKET_REQUEST = new TlsExtensionType(58, "ticket_request",
      true);
  public static final TlsExtensionType RENEGOTIATION_INFO = new TlsExtensionType(65281,
      "renegotiation_info", true);

  private static final Map<Integer, TlsExtensionType> LOOKUP = new HashMap<>();

  static {
    LOOKUP.put(SERVER_NAME.getValue(), SERVER_NAME);
    LOOKUP.put(MAX_FRAGMENT_LENGTH.getValue(), MAX_FRAGMENT_LENGTH);
    LOOKUP.put(CLIENT_CERTIFICATE_URL.getValue(), CLIENT_CERTIFICATE_URL);
    LOOKUP.put(TRUSTED_CA_KEYS.getValue(), TRUSTED_CA_KEYS);
    LOOKUP.put(TRUNCATED_HMAC.getValue(), TRUNCATED_HMAC);
    LOOKUP.put(STATUS_REQUEST.getValue(), STATUS_REQUEST);
    LOOKUP.put(USER_MAPPING.getValue(), USER_MAPPING);
    LOOKUP.put(CLIENT_AUTHZ.getValue(), CLIENT_AUTHZ);
    LOOKUP.put(SERVER_AUTHZ.getValue(), SERVER_AUTHZ);
    LOOKUP.put(CERT_TYPE.getValue(), CERT_TYPE);
    LOOKUP.put(SUPPORTED_GROUPS.getValue(), SUPPORTED_GROUPS);
    LOOKUP.put(EC_POINT_FORMATS.getValue(), EC_POINT_FORMATS);
    LOOKUP.put(SRP.getValue(), SRP);
    LOOKUP.put(SIGNATURE_ALGORITHMS.getValue(), SIGNATURE_ALGORITHMS);
    LOOKUP.put(USE_SRTP.getValue(), USE_SRTP);
    LOOKUP.put(HEARTBEAT.getValue(), HEARTBEAT);
    LOOKUP.put(APPLICATION_LAYER_PROTOCOL_NEGOTIATION.getValue(),
        APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
    LOOKUP.put(STATUS_REQUEST_V2.getValue(), STATUS_REQUEST_V2);
    LOOKUP.put(SIGNED_CERTIFICATE_TIMESTAMP.getValue(), SIGNED_CERTIFICATE_TIMESTAMP);
    LOOKUP.put(CLIENT_CERTIFICATE_TYPE.getValue(), CLIENT_CERTIFICATE_TYPE);
    LOOKUP.put(SERVER_CERTIFICATE_TYPE.getValue(), SERVER_CERTIFICATE_TYPE);
    LOOKUP.put(PADDING.getValue(), PADDING);
    LOOKUP.put(ENCRYPT_THEN_MAC.getValue(), ENCRYPT_THEN_MAC);
    LOOKUP.put(EXTENDED_MASTER_SECRET.getValue(), EXTENDED_MASTER_SECRET);
    LOOKUP.put(TOKEN_BINDING.getValue(), TOKEN_BINDING);
    LOOKUP.put(CACHED_INFO.getValue(), CACHED_INFO);
    LOOKUP.put(TLS_LTS.getValue(), TLS_LTS);
    LOOKUP.put(COMPRESS_CERTIFICATE.getValue(), COMPRESS_CERTIFICATE);
    LOOKUP.put(RECORD_SIZE_LIMIT.getValue(), RECORD_SIZE_LIMIT);
    LOOKUP.put(PWD_PROTECT.getValue(), PWD_PROTECT);
    LOOKUP.put(PWD_CLEAR.getValue(), PWD_CLEAR);
    LOOKUP.put(PASSWORD_SALT.getValue(), PASSWORD_SALT);
    LOOKUP.put(TICKET_PINNING.getValue(), TICKET_PINNING);
    LOOKUP.put(TLS_CERT_WITH_EXTERN_PSK.getValue(), TLS_CERT_WITH_EXTERN_PSK);
    LOOKUP.put(DELEGATED_CREDENTIALS.getValue(), DELEGATED_CREDENTIALS);
    LOOKUP.put(SESSION_TICKET.getValue(), SESSION_TICKET);
    LOOKUP.put(TLMSP.getValue(), TLMSP);
    LOOKUP.put(TLMSP_PROXYING.getValue(), TLMSP_PROXYING);
    LOOKUP.put(TLMSP_DELEGATE.getValue(), TLMSP_DELEGATE);
    LOOKUP.put(SUPPORTED_EKT_CIPHERS.getValue(), SUPPORTED_EKT_CIPHERS);
    LOOKUP.put(PRE_SHARED_KEY.getValue(), PRE_SHARED_KEY);
    LOOKUP.put(EARLY_DATA.getValue(), EARLY_DATA);
    LOOKUP.put(SUPPORTED_VERSIONS.getValue(), SUPPORTED_VERSIONS);
    LOOKUP.put(COOKIE.getValue(), COOKIE);
    LOOKUP.put(PSK_KEY_EXCHANGE_MODES.getValue(), PSK_KEY_EXCHANGE_MODES);
    LOOKUP.put(CERTIFICATE_AUTHORITIES.getValue(), CERTIFICATE_AUTHORITIES);
    LOOKUP.put(OID_FILTERS.getValue(), OID_FILTERS);
    LOOKUP.put(POST_HANDSHAKE_AUTH.getValue(), POST_HANDSHAKE_AUTH);
    LOOKUP.put(SIGNATURE_ALGORITHMS_CERT.getValue(), SIGNATURE_ALGORITHMS_CERT);
    LOOKUP.put(KEY_SHARE.getValue(), KEY_SHARE);
    LOOKUP.put(TRANSPARENCY_INFO.getValue(), TRANSPARENCY_INFO);
    LOOKUP.put(CONNECTION_ID.getValue(), CONNECTION_ID);
    LOOKUP.put(EXTERNAL_ID_HASH.getValue(), EXTERNAL_ID_HASH);
    LOOKUP.put(EXTERNAL_SESSION_ID.getValue(), EXTERNAL_SESSION_ID);
    LOOKUP.put(QUIC_TRANSPORT_PARAMETERS.getValue(), QUIC_TRANSPORT_PARAMETERS);
    LOOKUP.put(TICKET_REQUEST.getValue(), TICKET_REQUEST);
    LOOKUP.put(RENEGOTIATION_INFO.getValue(), RENEGOTIATION_INFO);
    LOOKUP.put(40, new TlsExtensionType(40, RESERVED, false));
    LOOKUP.put(46, new TlsExtensionType(46, RESERVED, false));
    LOOKUP.put(54, new TlsExtensionType(54, UNASSIGNED, false));
    for (int i = 59; i <= 2569; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(2570, new TlsExtensionType(2570, RESERVED, false));
    for (int i = 2571; i <= 6681; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(6682, new TlsExtensionType(6682, RESERVED, false));
    for (int i = 6683; i <= 10793; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(10794, new TlsExtensionType(10794, RESERVED, false));
    for (int i = 10795; i <= 14905; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(14906, new TlsExtensionType(14906, RESERVED, false));
    for (int i = 14907; i <= 19017; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(19018, new TlsExtensionType(19018, RESERVED, false));
    for (int i = 19019; i <= 23129; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(23130, new TlsExtensionType(23130, RESERVED, false));
    for (int i = 23131; i <= 27241; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(27242, new TlsExtensionType(27242, RESERVED, false));
    for (int i = 27243; i <= 31353; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(31354, new TlsExtensionType(31354, RESERVED, false));
    for (int i = 31355; i <= 35465; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(35466, new TlsExtensionType(35466, RESERVED, false));
    for (int i = 35467; i <= 39577; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(39578, new TlsExtensionType(39578, RESERVED, false));
    for (int i = 39579; i <= 43689; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(43690, new TlsExtensionType(43690, RESERVED, false));
    for (int i = 43691; i <= 47801; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(47802, new TlsExtensionType(47802, RESERVED, false));
    for (int i = 47803; i <= 51913; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(51914, new TlsExtensionType(51914, RESERVED, false));
    for (int i = 51915; i <= 56025; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(56026, new TlsExtensionType(56026, RESERVED, false));
    for (int i = 56027; i <= 60137; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(60138, new TlsExtensionType(60138, RESERVED, false));
    for (int i = 60139; i <= 64249; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(64250, new TlsExtensionType(64250, RESERVED, false));
    for (int i = 64251; i <= 65279; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, UNASSIGNED, false));
    }
    LOOKUP.put(65280, new TlsExtensionType(65280, RESERVED_FOR_PRIVATE_USE, false));
    for (int i = 65282; i <= 65535; i++) {
      LOOKUP.put(i, new TlsExtensionType(i, RESERVED_FOR_PRIVATE_USE, false));
    }
  }

  private int value;
  private String name;
  private boolean recommended;

  public TlsExtensionType(int value, String name, boolean recommended) {
    this.value = value;
    this.name = name;
    this.recommended = recommended;
  }

  public int getValue() {
    return this.value;
  }

  public byte[] getBytes() {
    return TlsUtils.enc16be(value, new byte[2]);
  }

  public String getName() {
    return name;
  }

  public boolean isRecommended() {
    return recommended;
  }

  public boolean isReserved() {
    return RESERVED.equals(this.name);
  }

  public boolean isUnassigned() {
    return UNASSIGNED.equals(this.name);
  }

  public boolean isReservedForPrivateUse() {
    return RESERVED_FOR_PRIVATE_USE.equals(this.name);
  }

  public boolean isValid() {
    return !isReserved() && !isUnassigned() && !isReservedForPrivateUse();
  }

  public static TlsExtensionType of(byte[] bytes) throws TlsProtocolException {
    int key = TlsUtils.dec16be(bytes);
    if (LOOKUP.containsKey(key)) {
      return LOOKUP.get(TlsUtils.dec16be(bytes));
    }
    throw new TlsProtocolException("Invalid ExtensionType[" + TlsUtils.toString(bytes) + "]");
  }

  @Override
  public String toString() {
    return !isValid() ? String.format("%s(%s)", this.name, getValue()) : this.name;
  }

}
