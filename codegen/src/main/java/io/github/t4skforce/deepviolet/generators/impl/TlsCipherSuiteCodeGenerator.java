package io.github.t4skforce.deepviolet.generators.impl;

import static io.github.t4skforce.deepviolet.generators.util.JavaPoetUtils.assertEquals;
import static io.github.t4skforce.deepviolet.generators.util.JavaPoetUtils.assertNotNull;
import static io.github.t4skforce.deepviolet.generators.util.JavaPoetUtils.assertTrue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.squareup.javapoet.AnnotationSpec;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;

import io.github.t4skforce.deepviolet.generators.util.HtmlUtils;
import io.github.t4skforce.deepviolet.generators.util.JavaPoetUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TlsCipherSuiteCodeGenerator extends MultiHttpRequestCodeGenerator {

  private static final String NAME_GREASE = "GREASE";

  private static final String NAME_RESERVED = "RESERVED";

  private static final String NAME_UNASSIGNED = "UNASSIGNED";

  private static final String NAME_FORMAT = "%s:(0x%04X)";

  private static final Logger LOG = LoggerFactory.getLogger(TlsCipherSuiteCodeGenerator.class);

  private static final String TARGET_CLASS_NAME = "io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake.CipherSuite";

  protected static final String IANA_URL = "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml";
  protected static final String NSS_URL = "https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ssl/sslproto.h";
  protected static final String OPENSSL_URL = "https://raw.githubusercontent.com/openssl/openssl/master/include/openssl/tls1.h";
  protected static final String GNUTLS_URL = "https://gitlab.com/gnutls/gnutls/raw/master/lib/algorithms/ciphersuites.c";

  private static final Pattern REGEX_NSS = Pattern.compile("#\\s*define\\s+(?<name>TLS_[^\\s]+)\\s+0x(?<hex>[A-F|0-9]{4})", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private static final Pattern REGEX_OPENSSL = Pattern.compile("#\\s*define\\s+TLS1_([0-9]_)?CK_(?<name>[^\\s]+)\\s+0x(?<hex>[A-F|0-9]{8})", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private static final Pattern REGEX_OPENSSL_NAMES = Pattern.compile("#\\s*define\\s+TLS1_TXT_(?<key>[^\\s]+)\\s+\"(?<value>[^\"]+)\"", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  private static final Pattern REGEX_GNUTLS_NAMES = Pattern.compile("#\\s*define\\s*GNU(?<name>TLS_[^\\s]+)\\s*\\{\\s*0x(?<hex1>[A-F|0-9]{2})\\s*,\\s*0x(?<hex2>[A-F|0-9]{2})\\s*\\}",
      Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

//https://tools.ietf.org/html/draft-davidben-tls-grease-01#section-5
  private static final Set<Integer> GREASE = new HashSet<>(Arrays.asList(2570, // {0x0A,0x0A}
      6682, // {0x1A,0x1A}
      10794, // {0x2A,0x2A}
      14906, // {0x3A,0x3A}
      19018, // {0x4A,0x4A}
      23130, // {0x5A,0x5A}
      27242, // {0x6A,0x6A}
      31354, // {0x7A,0x7A}
      35466, // {0x8A,0x8A}
      39578, // {0x9A,0x9A}
      43690, // {0xAA,0xAA}
      47802, // {0xBA,0xBA}
      51914, // {0xCA,0xCA}
      56026, // {0xDA,0xDA}
      60138, // {0xEA,0xEA}
      64250 // {0xFA,0xFA}
  ));

  private Map<Integer, TlsCipherSuiteWrapper> LOOKUP = new HashMap<>();

  private class TlsCipherSuiteWrapper implements Comparable<TlsCipherSuiteWrapper> {
    protected String iana = StringUtils.EMPTY;
    protected String nss = StringUtils.EMPTY;
    protected String openssl = StringUtils.EMPTY;
    protected String gnutls = StringUtils.EMPTY;
    protected List<String> refs = new ArrayList<>();
    protected boolean recommended;
    protected boolean dtlsok;
    protected int from;
    protected int to;

    public TlsCipherSuiteWrapper(int from, int to, String iana, boolean dtlsok, boolean recommended, List<String> refs) {
      this.from = from;
      this.to = to;
      this.iana = iana;
      this.recommended = recommended;
      this.dtlsok = dtlsok;
      this.refs = refs;
    }

    public boolean isRange() {
      return from < to;
    }

    public boolean isUnassigned() {
      return StringUtils.startsWithIgnoreCase(iana, "Unassigned");
    }

    public boolean isReserved() {
      return StringUtils.startsWithIgnoreCase(iana, "Reserved");
    }

    public boolean isReservedPrivate() {
      return isReserved() && StringUtils.containsIgnoreCase(iana, "Private");
    }

    public boolean isGrease() {
      return !isRange() && GREASE.contains(this.from);
    }

    public boolean hasAlternativeName() {
      return StringUtils.isNoneEmpty(this.nss) || StringUtils.isNoneEmpty(this.openssl) || StringUtils.isNoneEmpty(this.gnutls);
    }

    public String getAlternativeName() {
      if (StringUtils.isNoneEmpty(this.nss)) {
        return this.nss;
      } else if (StringUtils.isNoneEmpty(this.openssl)) {
        return this.openssl;
      } else if (StringUtils.isNoneEmpty(this.gnutls)) {
        return this.gnutls;
      }
      return StringUtils.EMPTY;
    }

    @Override
    public int compareTo(TlsCipherSuiteWrapper o) {
      return Integer.valueOf(this.from).compareTo(Integer.valueOf(o.from));
    }
  }

  public TlsCipherSuiteCodeGenerator() throws Exception {
    super();
  }

  @Override
  protected String getClassName() {
    return TARGET_CLASS_NAME;
  }

  @Override
  protected List<ResponseProcessor> getProcessors() {
    return ResponseProcessor.builder().get(IANA_URL, this::processIana).get(NSS_URL, this::processNss).get(OPENSSL_URL, this::processOpenSsl).get(GNUTLS_URL, this::processGnuTls).build();
  }

  private void processIana(CloseableHttpResponse response) throws Exception {
    LOG.info("Processing IANA");
    HtmlUtils.elems(response, "#table-tls-parameters-4 tbody tr").orElseThrow(() -> {
      return new IOException("Could not find Iana data");
    }).forEach(elem -> {
      String value = elem.select("td:eq(0)").first().text();
      // fixup ranges
      if (StringUtils.contains(value, "*")) {
        value = StringUtils.replace(value, "*", "0x00-FF");
      }
      Boolean isRanged = StringUtils.contains(value, '-');
      Integer from = null;
      Integer to = null;
      if (isRanged) {
        String hexFrom = Arrays.asList(StringUtils.split(value, ',')).stream().map(v -> StringUtils.strip(v)).map(v -> StringUtils.removeStartIgnoreCase(v, "0x"))
            .map(v -> StringUtils.split(v, '-')[0]).collect(Collectors.joining(""));

        String hexTo = Arrays.asList(StringUtils.split(value, ',')).stream().map(v -> StringUtils.strip(v)).map(v -> StringUtils.removeStartIgnoreCase(v, "0x")).map(v -> {
          String[] pt = StringUtils.split(v, '-');
          return pt[pt.length - 1];
        }).collect(Collectors.joining(""));

        from = Integer.parseUnsignedInt(hexFrom, 16);
        to = Integer.parseUnsignedInt(hexTo, 16);
      } else {
        String hexVal = Arrays.asList(StringUtils.split(value, ',')).stream().map(v -> StringUtils.strip(v)).map(v -> StringUtils.removeStartIgnoreCase(v, "0x")).collect(Collectors.joining(""));
        from = to = Integer.parseUnsignedInt(hexVal, 16);
      }
      String description = elem.select("td:eq(1)").first().text();
      Boolean dtlsok = BooleanUtils.toBoolean(elem.select("td:eq(2)").first().text());
      Boolean recommended = BooleanUtils.toBoolean(elem.select("td:eq(3)").first().text());
      List<String> refs = elem.select("td:eq(4) a").stream().map(e -> e.outerHtml()).collect(Collectors.toList());

      if (from < to) {
        Integer grIdx;
        while ((grIdx = getGreaseInRange(from, to)) != null) {
          LOOKUP.put(from, new TlsCipherSuiteWrapper(from, grIdx - 1, description, dtlsok, recommended, refs));
          LOOKUP.put(from, new TlsCipherSuiteWrapper(grIdx, grIdx, description, dtlsok, recommended, refs));
          from = grIdx + 1;
        }
        LOOKUP.put(from, new TlsCipherSuiteWrapper(from, to, description, dtlsok, recommended, refs));
      } else {
        LOOKUP.put(from, new TlsCipherSuiteWrapper(from, to, description, dtlsok, recommended, refs));
      }

    });

    // ensure no empty spaces
    int previousKey = 0;
    boolean previousMissing = false;
    for (int i = 0x0000; i <= 0xFFFF; i++) {
      final int key = i;
      if (!LOOKUP.containsKey(key)) {
        // get previous key
        boolean missing = LOOKUP.values().stream().filter(v -> v.from <= key && v.to >= key).findFirst().isEmpty();
        if (missing) {
          if (previousMissing) {
            LOOKUP.get(previousKey).to = key;
          } else {
            previousKey = key;
            LOOKUP.put(key, new TlsCipherSuiteWrapper(key, key, "Unassigned", false, false, Collections.emptyList()));
            LOG.warn("IANA from:{} not found", String.format("0x%04X", key));
          }
        }
        previousMissing = missing;
      }
    }

    LOG.info("Processed IANA {} entries", LOOKUP.size());
  }

  private Integer getGreaseInRange(Integer from, Integer to) {
    for (int i = from; i <= to; i++) {
      if (GREASE.contains(i)) {
        return i;
      }
    }
    return null;
  }

  private void processNss(String content) throws Exception {
    LOG.info("Processing NSS");
    int cnt = 0;
    Matcher sources = REGEX_NSS.matcher(content);
    while (sources.find()) {
      String hexVal = sources.group("hex").trim();
      Integer from = Integer.parseUnsignedInt(hexVal, 16);
      String name = sources.group("name").trim().toUpperCase();
      getWrapper(from).ifPresentOrElse(suite -> {
        if (suite.isRange()) {
          LOG.warn("NSS key:{} name:{} found in iana key:{}-{} name:{}", hexVal, name, suite.from, suite.to, suite.iana);
          TlsCipherSuiteWrapper thisWrap = new TlsCipherSuiteWrapper(from, from, suite.iana, suite.dtlsok, suite.recommended, suite.refs);
          thisWrap.nss = name;
          splitUp(from, suite, thisWrap);
        } else {
          suite.nss = name;
        }
      }, () -> {
        // TODO: split up iana entries and add found
        LOG.warn("NSS key:{} name:{} not found in iana", hexVal, name);
      });
      cnt++;
    }
    LOG.info("Processed NSS {} entries", cnt);
  }

  private void splitUp(Integer from, TlsCipherSuiteWrapper suite, TlsCipherSuiteWrapper thisWrap) {
    if (from == suite.from) {
      suite.from++;
      LOOKUP.put(suite.from, suite);
      LOOKUP.put(from, thisWrap);
    } else if (from == suite.to) {
      suite.to--;
      LOOKUP.put(from, thisWrap);
    } else {
      TlsCipherSuiteWrapper beforeWrap = new TlsCipherSuiteWrapper(suite.from, from - 1, suite.iana, suite.dtlsok, suite.recommended, suite.refs);
      TlsCipherSuiteWrapper afterWrap = new TlsCipherSuiteWrapper(from + 1, suite.to, suite.iana, suite.dtlsok, suite.recommended, suite.refs);
      LOOKUP.put(beforeWrap.from, beforeWrap);
      LOOKUP.put(from, thisWrap);
      LOOKUP.put(afterWrap.from, afterWrap);
    }
  }

  public Optional<TlsCipherSuiteWrapper> getWrapper(int value) {
    if (LOOKUP.containsKey(value)) {
      return Optional.of(LOOKUP.get(value));
    }
    return LOOKUP.values().stream().filter(v -> v.from <= value && v.to >= value).findFirst();
  }

  private void processOpenSsl(String content) throws Exception {
    LOG.info("Processing OpenSSL");
    // mapping e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> ECDHE-RSA-AES128-GCM-SHA256
    Map<String, String> mapping = new HashMap<>();
    Matcher sources = REGEX_OPENSSL_NAMES.matcher(content);
    while (sources.find()) {
      String key = sources.group("key").trim().toUpperCase();
      String value = sources.group("value").trim().toUpperCase();
      mapping.put(key, value);
    }

    int cnt = 0;
    sources = REGEX_OPENSSL.matcher(content);
    while (sources.find()) {
      String lname = sources.group("name").trim().toUpperCase();
      final String name = mapping.get(lname);
      String lhexVal = sources.group("hex").trim().toUpperCase();
      final String hexVal = StringUtils.join(lhexVal.substring(4, 6), lhexVal.substring(6, 8));
      Integer from = Integer.parseUnsignedInt(hexVal, 16);
      getWrapper(from).ifPresentOrElse(suite -> {
        if (suite.isRange()) {
          LOG.warn("OpenSSL key:{} name:{} found in iana key:{}-{} name:{}", hexVal, name, suite.from, suite.to, suite.iana);
          TlsCipherSuiteWrapper thisWrap = new TlsCipherSuiteWrapper(from, from, suite.iana, suite.dtlsok, suite.recommended, suite.refs);
          thisWrap.openssl = name;
          splitUp(from, suite, thisWrap);
        } else {
          suite.openssl = name;
        }
      }, () -> {
        LOG.warn("OpenSSL key:{} name:{} not found in iana", hexVal, name);
      });
      cnt++;
    }
    LOG.info("Processed OpenSSL {} entries", cnt);
  }

  private void processGnuTls(String content) throws Exception {
    LOG.info("Processing GnuTLS");
    int cnt = 0;
    Matcher sources = REGEX_GNUTLS_NAMES.matcher(content);
    while (sources.find()) {
      String name = sources.group("name").trim().toUpperCase();
      String hexVal = StringUtils.join(sources.group("hex1").trim(), sources.group("hex2").trim());
      Integer from = Integer.parseUnsignedInt(hexVal, 16);
      getWrapper(from).ifPresentOrElse(suite -> {
        if (suite.isRange()) {
          LOG.warn("GnuTLS key:{} name:{} found in iana key:{}-{} name:{}", hexVal, name, suite.from, suite.to, suite.iana);
          TlsCipherSuiteWrapper thisWrap = new TlsCipherSuiteWrapper(from, from, suite.iana, suite.dtlsok, suite.recommended, suite.refs);
          thisWrap.gnutls = name;
          splitUp(from, suite, thisWrap);
        } else {
          suite.gnutls = name;
        }
      }, () -> {
        LOG.warn("GnuTLS key:{} name:{} not found in iana", hexVal, name);
      });
      cnt++;
    }
    LOG.info("Processed GnuTLS {} entries", cnt);
  }

  @Override
  protected void after() throws Exception {
    LOG.info("Building Pojo Class");
    typeSpec.addJavadoc("<br/>This class is based on <a href=$S>www.iana.org</a> specification and enhanced with <a href=$S>mozilla.org</a>, <a href=$S>OpenSSL</a> and <a href=$S>GnuTLS</a>",
        IANA_URL, NSS_URL, OPENSSL_URL, GNUTLS_URL);
    typeSpec.addAnnotation(AnnotationSpec.builder(ClassName.get("io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations", "TlsCipherSuite")).build());

    // static strings
    FieldSpec staticNameFormat = FieldSpec.builder(String.class, "NAME_FORMAT", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_FORMAT).build();
    typeSpec.addField(staticNameFormat);
    FieldSpec staticUnassigned = FieldSpec.builder(String.class, NAME_UNASSIGNED, Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_UNASSIGNED).build();
    typeSpec.addField(staticUnassigned);
    FieldSpec staticReserved = FieldSpec.builder(String.class, NAME_RESERVED, Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_RESERVED).build();
    typeSpec.addField(staticReserved);
    FieldSpec staticGrease = FieldSpec.builder(String.class, NAME_GREASE, Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_GREASE).build();
    typeSpec.addField(staticGrease);

    // static lookup section
    FieldSpec staticValueMap = FieldSpec
        .builder(ParameterizedTypeName.get(ClassName.get(Map.class), ClassName.get(Integer.class), self), "VALUE_MAP", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
        .initializer("new $T<>()", HashMap.class).build();
    FieldSpec staticNameMap = FieldSpec.builder(ParameterizedTypeName.get(ClassName.get(Map.class), ClassName.get(String.class), self), "NAME_MAP", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
        .initializer("new $T<>()", HashMap.class).build();

    // Generate static instance fields
    CodeBlock.Builder lookupInit = CodeBlock.builder();
    List<FieldSpec> staticFields = new ArrayList<>();

    List<TlsCipherSuiteWrapper> suites = new ArrayList<TlsCipherSuiteWrapper>(LOOKUP.values());
    Collections.sort(suites);
    for (TlsCipherSuiteWrapper suite : suites) {
      if (!suite.isRange() && !suite.isUnassigned() && !suite.isReserved()) {
        FieldSpec staticField = FieldSpec.builder(self, suite.iana.toUpperCase(), Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL)
            .initializer(CodeBlock.of("new $T($N,\n      $S,\n      $S,\n      $S,\n      $S,\n      $L,\n      $L)", self, String.format("0x%04X", suite.from), suite.iana, suite.nss, suite.openssl,
                suite.gnutls, suite.dtlsok, suite.recommended))
            .addJavadoc(
                "Static variable for SipherSuite.<br/>\n<strong>IANA:</strong> $L<br/>\n<strong>NSS:</strong> $L<br/>\n<strong>OpenSSL:</strong> $L<br/>\n<strong>GnuTLS:</strong> $L<br/>\n<strong>DTLS-OK:</strong> $L<br/>\n<strong>Recommended:</strong> $L<br/>\n<strong>References:</strong> $L",
                suite.iana, suite.nss, suite.openssl, suite.gnutls, suite.dtlsok, suite.recommended, StringUtils.join(suite.refs, ", "))
            .build();
        staticFields.add(staticField);
      } else if (!suite.isRange() && suite.hasAlternativeName()) {
        FieldSpec staticField = FieldSpec.builder(self, suite.getAlternativeName().toUpperCase(), Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL)
            .initializer(CodeBlock.of("new $T($N,\n      $S,\n      $S,\n      $S,\n      $S,\n      $L,\n      $L,\n      $L,\n      $L,\n      $L)", self, String.format("0x%04X", suite.from),
                suite.iana, suite.nss, suite.openssl, suite.gnutls, suite.dtlsok, suite.recommended, suite.isReserved(), suite.isUnassigned(), suite.isGrease()))
            .addJavadoc(
                "Static variable for SipherSuite.<br/>\n<strong>IANA:</strong> $L<br/>\n<strong>NSS:</strong> $L<br/>\n<strong>OpenSSL:</strong> $L<br/>\n<strong>GnuTLS:</strong> $L<br/>\n<strong>DTLS-OK:</strong> $L<br/>\n<strong>Recommended:</strong> $L<br/>\n<strong>Reserved:</strong> $L<br/>\n<strong>Unassigned:</strong> $L<br/>\n<strong>Grease:</strong> $L<br/>\n<strong>References:</strong> $L",
                suite.iana, suite.nss, suite.openssl, suite.gnutls, suite.dtlsok, suite.recommended, suite.isReserved(), suite.isUnassigned(), suite.isGrease(), StringUtils.join(suite.refs, ", "))
            .build();
        staticFields.add(staticField);
      } else if (suite.isRange()) {
        lookupInit.add(CodeBlock.builder().beginControlFlow("for (int i = $L; i <= $L; i++)", String.format("0x%04X", suite.from), String.format("0x%04X", suite.to))
            .addStatement("new $T(i, $S, $L, $L)", self, suite.iana, suite.isReserved(), suite.isUnassigned()).endControlFlow().build());
      } else if (suite.isUnassigned() || suite.isReserved() || suite.isGrease()) {
        lookupInit.addStatement("new $T($N, $S, $L, $L, $L)", self, String.format("0x%04X", suite.from), suite.iana, suite.isReserved(), suite.isUnassigned(), suite.isGrease());
      }
    }

    typeSpec.addField(staticValueMap);
    typeSpec.addField(staticNameMap);
    typeSpec.addFields(staticFields);
    typeSpec.addStaticBlock(lookupInit.build());

    // private fields
    FieldSpec value = FieldSpec.builder(TypeName.INT, "value", Modifier.PRIVATE).build();
    FieldSpec iana = FieldSpec.builder(String.class, "iana", Modifier.PRIVATE).build();
    FieldSpec nss = FieldSpec.builder(String.class, "nss", Modifier.PRIVATE).build();
    FieldSpec openssl = FieldSpec.builder(String.class, "openSsl", Modifier.PRIVATE).build();
    FieldSpec gnutls = FieldSpec.builder(String.class, "gnuTls", Modifier.PRIVATE).build();

    FieldSpec dtlsok = FieldSpec.builder(TypeName.BOOLEAN, "dtlsOk", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    FieldSpec recommended = FieldSpec.builder(TypeName.BOOLEAN, "recommended", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    FieldSpec reserved = FieldSpec.builder(TypeName.BOOLEAN, "reserved", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    FieldSpec unassigned = FieldSpec.builder(TypeName.BOOLEAN, "unassigned", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    FieldSpec grease = FieldSpec.builder(TypeName.BOOLEAN, "grease", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    typeSpec.addFields(Arrays.asList(value, iana, nss, openssl, gnutls, dtlsok, recommended, reserved, unassigned, grease));

    // private default constructor
    typeSpec.addMethod(MethodSpec.constructorBuilder().addModifiers(Modifier.PRIVATE).addStatement("super()").build());

    // getName method spec
    CodeBlock nameBlock = CodeBlock.builder().beginControlFlow("if ($T.isNotEmpty(this.$N))", StringUtils.class, nss).addStatement("return this.$N", nss)
        .nextControlFlow("else if ($T.isNotEmpty(this.$N))", StringUtils.class, openssl).addStatement("return this.$N", openssl)
        .nextControlFlow("else if ($T.isNotEmpty(this.$N))", StringUtils.class, gnutls).addStatement("return this.$N", gnutls).endControlFlow().build();
    MethodSpec getName = MethodSpec.methodBuilder("getName").addModifiers(Modifier.PUBLIC).returns(String.class).addAnnotation(JsonValue.class).beginControlFlow("if (this.$N)", grease)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticGrease, value).nextControlFlow("else if (this.$N)", unassigned).addCode(nameBlock)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticUnassigned, value).nextControlFlow("else if (this.$N)", reserved).addCode(nameBlock)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticReserved, value).nextControlFlow("else").addStatement("return this.$N", iana).endControlFlow().build();

    CodeBlock addToLookupCodeBlock = CodeBlock.builder().addStatement("$N.put(this.$N(), this)", staticNameMap, getName).addStatement("$N.put(this.$N, this)", staticValueMap, value).build();

    // private constructor using fields
    MethodSpec.Builder ctor = JavaPoetUtils.privateConstructor(value, iana, reserved, unassigned).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // private constructor using fields
    ctor = JavaPoetUtils.privateConstructor(value, iana, reserved, unassigned, grease).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // private constructor using fields
    ctor = JavaPoetUtils.privateConstructor(value, iana, nss, openssl, gnutls, dtlsok, recommended).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // private constructor using fields
    ctor = JavaPoetUtils.privateConstructor(value, iana, nss, openssl, gnutls, dtlsok, recommended, reserved, unassigned, grease).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // generate public getter in pojo
    typeSpec.addMethods(JavaPoetUtils.getter(value, iana, nss, openssl, gnutls, dtlsok, recommended, reserved, unassigned, grease));

    // getName
    typeSpec.addMethod(getName);

    // of(Integer value)
    typeSpec.addMethod(MethodSpec.methodBuilder("of").addAnnotation(JsonCreator.class).addModifiers(Modifier.PUBLIC, Modifier.STATIC).addParameter(int.class, "value").returns(self)
        .addStatement("return $N.get($N)", staticValueMap, "value").build());

    // of(String value)
    typeSpec.addMethod(MethodSpec.methodBuilder("of").addAnnotation(JsonCreator.class).addModifiers(Modifier.PUBLIC, Modifier.STATIC).addParameter(String.class, "name").returns(self)
        .addStatement("return $N.get($N)", staticNameMap, "name").build());

    // toString
    typeSpec.addMethod(MethodSpec.methodBuilder("toString").addAnnotation(Override.class).addModifiers(Modifier.PUBLIC).returns(String.class).addStatement("return $N()", getName).build());

    LOG.info("Buit Pojo Class");
  }

  private String toCamelCase(String str) {
    return StringUtils.join(Arrays.asList(str.split("_")).stream().map(s -> StringUtils.capitalize(s)).collect(Collectors.toList()), "");
  }

  @Override
  protected void afterTest() throws Exception {
    List<TlsCipherSuiteWrapper> suites = new ArrayList<TlsCipherSuiteWrapper>(LOOKUP.values());
    Collections.sort(suites);
    for (TlsCipherSuiteWrapper suite : suites) {
      if (!suite.isRange() && !suite.isUnassigned() && !suite.isReserved()) {
        testSpec.addMethod(JavaPoetUtils.test(StringUtils.join("StaticGet", toCamelCase(suite.iana.toLowerCase()))).addStatement("$T suite = $T.$L", self, self, suite.iana.toUpperCase())
            .addStatement("$T($T.of($N), suite)", assertEquals, self, String.format("0x%04X", suite.from)).addStatement("$T($N, suite.getValue())", assertEquals, String.format("0x%04X", suite.from))
            .addStatement("$T($S, suite.getName())", assertEquals, suite.iana).addStatement("$T($S, suite.getIana())", assertEquals, suite.iana)
            .addStatement("$T($S, suite.getNss())", assertEquals, suite.nss).addStatement("$T($S, suite.getOpenSsl())", assertEquals, suite.openssl)
            .addStatement("$T($S, suite.getGnuTls())", assertEquals, suite.gnutls).addStatement("$T($L, suite.isDtlsOk())", assertEquals, suite.dtlsok)
            .addStatement("$T($L, suite.isRecommended())", assertEquals, suite.recommended).addStatement("$T($L, suite.isReserved())", assertEquals, suite.isReserved())
            .addStatement("$T($L, suite.isUnassigned())", assertEquals, suite.isUnassigned()).addStatement("$T($L, suite.isGrease())", assertEquals, suite.isGrease()).build());
      } else if (!suite.isRange() && suite.hasAlternativeName()) {
        testSpec.addMethod(JavaPoetUtils.test(StringUtils.join("StaticGet", toCamelCase(suite.getAlternativeName())))
            .addStatement("$T suite = $T.$L", self, self, suite.getAlternativeName().toUpperCase()).addStatement("$T($T.of($N), suite)", assertEquals, self, String.format("0x%04X", suite.from))
            .addStatement("$T($N, suite.getValue())", assertEquals, String.format("0x%04X", suite.from)).addStatement("$T($S, suite.getName())", assertEquals, suite.getAlternativeName())
            .addStatement("$T($S, suite.getIana())", assertEquals, suite.iana).addStatement("$T($S, suite.getNss())", assertEquals, suite.nss)
            .addStatement("$T($S, suite.getOpenSsl())", assertEquals, suite.openssl).addStatement("$T($S, suite.getGnuTls())", assertEquals, suite.gnutls)
            .addStatement("$T($L, suite.isDtlsOk())", assertEquals, suite.dtlsok).addStatement("$T($L, suite.isRecommended())", assertEquals, suite.recommended)
            .addStatement("$T($L, suite.isReserved())", assertEquals, suite.isReserved()).addStatement("$T($L, suite.isUnassigned())", assertEquals, suite.isUnassigned())
            .addStatement("$T($L, suite.isGrease())", assertEquals, suite.isGrease()).build());
      }
    }

    CodeBlock.Builder cb = CodeBlock.builder();
    cb.beginControlFlow("for (int i=0x0000; i<=0xFFFF; i++)").addStatement("$T($T.of(i), $T.format($S, i))", assertNotNull, self, String.class, self.simpleName() + ".of(0x%04X)")
        .addStatement("$T($T.of(i) == $T.of(i))", assertTrue, self, self).addStatement("$T($T.of(i) == $T.of($T.of(i).getName()))", assertTrue, self, self, self)
        .addStatement("$T($T.of($T.of(i).toString()) == $T.of($T.of(i).getName()))", assertTrue, self, self, self, self).endControlFlow();
    testSpec.addMethod(JavaPoetUtils.test("testFullRange").addCode(cb.build()).build());
  }

}
