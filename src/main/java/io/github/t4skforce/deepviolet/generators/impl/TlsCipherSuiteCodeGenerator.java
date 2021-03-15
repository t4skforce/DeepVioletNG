package io.github.t4skforce.deepviolet.generators.impl;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.squareup.javapoet.AnnotationSpec;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;

import io.github.t4skforce.deepviolet.generators.util.HtmlUtil;
import io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations.TlsCipherSuite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
    protected boolean recommended;
    protected boolean dtlsok;
    protected int from;
    protected int to;

    public TlsCipherSuiteWrapper(int from, int to, String iana, boolean dtlsok, boolean recommended) {
      this.from = from;
      this.to = to;
      this.iana = iana;
      this.recommended = recommended;
      this.dtlsok = dtlsok;
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

  @Override
  protected void before() throws Exception {
    // nothing to do
    generator.setChanged(true);
  }

  @Override
  protected void beforeTest() throws Exception {
    // nothing to do
    generator.setChanged(true);
  }

  private void processIana(CloseableHttpResponse response) throws Exception {
    LOG.info("Processing IANA");
    HtmlUtil.elems(response, "#table-tls-parameters-4 tbody tr").orElseThrow(() -> {
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

      if (from < to) {
        Integer grIdx;
        while ((grIdx = getGreaseInRange(from, to)) != null) {
          LOOKUP.put(from, new TlsCipherSuiteWrapper(from, grIdx - 1, description, dtlsok, recommended));
          LOOKUP.put(from, new TlsCipherSuiteWrapper(grIdx, grIdx, description, dtlsok, recommended));
          from = grIdx + 1;
        }
        LOOKUP.put(from, new TlsCipherSuiteWrapper(from, to, description, dtlsok, recommended));
      } else {
        LOOKUP.put(from, new TlsCipherSuiteWrapper(from, to, description, dtlsok, recommended));
      }

    });
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
      if (!LOOKUP.containsKey(from)) {
        // TODO: split up iana entries and add found
        LOG.warn("NSS key:{} name:{} not found in iana", hexVal, name);
        continue;
      }
      LOOKUP.get(from).nss = name;
      cnt++;
    }
    LOG.info("Processed NSS {} entries", cnt);
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
      String name = sources.group("name").trim().toUpperCase();
      name = mapping.get(name);
      String hexVal = sources.group("hex").trim().toUpperCase();
      hexVal = StringUtils.join(hexVal.substring(4, 6), hexVal.substring(6, 8));
      Integer from = Integer.parseUnsignedInt(hexVal, 16);

      if (!LOOKUP.containsKey(from)) {
        // TODO: split up iana entries and add found
        LOG.warn("OpenSSL key:{} name:{} not found in iana", hexVal, name);
        continue;
      }
      LOOKUP.get(from).openssl = name;
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
      if (!LOOKUP.containsKey(from)) {
        // TODO: split up iana entries and add found
        LOG.warn("GnuTLS key:{} name:{} not found in iana", hexVal, name);
        continue;
      }
      LOOKUP.get(from).gnutls = name;
      cnt++;
    }
    LOG.info("Processed GnuTLS {} entries", cnt);
  }

  @Override
  protected void after() throws Exception {
    LOG.info("Building Pojo Class");
    typeSpec.addJavadoc("<br/>This class is based on <a href=$S>www.iana.org</a> specification and enhanced with <a href=$S>mozilla.org</a>, <a href=$S>OpenSSL</a> and <a href=$S>GnuTLS</a>",
        IANA_URL, NSS_URL, OPENSSL_URL, GNUTLS_URL);
    typeSpec.addAnnotation(AnnotationSpec.builder(TlsCipherSuite.class).build());

    // static strings
    FieldSpec staticNameFormat = FieldSpec.builder(String.class, "NAME_FORMAT", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "%s:(0x%04X)").build();
    typeSpec.addField(staticNameFormat);
    FieldSpec staticUnassigned = FieldSpec.builder(String.class, "UNASSIGNED", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "UNASSIGNED").build();
    typeSpec.addField(staticUnassigned);
    FieldSpec staticReserved = FieldSpec.builder(String.class, "RESERVED", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "RESERVED").build();
    typeSpec.addField(staticReserved);
    FieldSpec staticGrease = FieldSpec.builder(String.class, "GREASE", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "GREASE").build();
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
                "Static variable for SipherSuite.<br/>\n<strong>IANA:</strong> $L<br/>\n<strong>NSS:</strong> $L<br/>\n<strong>OpenSSL:</strong> $L<br/>\n<strong>GnuTLS:</strong> $L<br/>\n<strong>DTLS-OK:</strong> $L<br/>\n<strong>Recommended:</strong> $L<br/>",
                suite.iana, suite.nss, suite.openssl, suite.gnutls, suite.dtlsok, suite.recommended)
            .build();
        staticFields.add(staticField);
        // lookupInit.addStatement("$N.put($N, $L)", staticLookup, String.format("0x%04X", suite.from), staticField.name);
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
    MethodSpec getName = MethodSpec.methodBuilder("getName").addModifiers(Modifier.PUBLIC).returns(String.class).addAnnotation(JsonValue.class).beginControlFlow("if (this.$N)", unassigned)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticUnassigned, value).nextControlFlow("else if (this.$N)", reserved)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticReserved, value).nextControlFlow("else if (this.$N)", grease)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticGrease, value).nextControlFlow("else").addStatement("return this.$N", iana).endControlFlow().build();

    CodeBlock addToLookupCodeBlock = CodeBlock.builder().addStatement("$N.put(this.$N(), this)", staticNameMap, getName).addStatement("$N.put(this.$N, this)", staticValueMap, value).build();

    // private constructor using fields
    MethodSpec.Builder ctor = ctorUsingFields(value, iana, reserved, unassigned).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // private constructor using fields
    ctor = ctorUsingFields(value, iana, reserved, unassigned, grease).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // private constructor using fields
    ctor = ctorUsingFields(value, iana, nss, openssl, gnutls, dtlsok, recommended).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // private constructor using fields
    ctor = ctorUsingFields(value, iana, nss, openssl, gnutls, dtlsok, recommended, reserved, unassigned, grease).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // generate public getter in pojo
    typeSpec.addMethods(generateGetter(value, iana, nss, openssl, gnutls, dtlsok, recommended, reserved, unassigned, grease));

    // getName
    typeSpec.addMethod(getName);

    // of(Integer value)
    typeSpec.addMethod(MethodSpec.methodBuilder("of").addAnnotation(JsonCreator.class).addModifiers(Modifier.PUBLIC, Modifier.STATIC).addParameter(int.class, "value").returns(self)
        .addStatement("return $N.get($N)", staticValueMap, "value").build());

    // of(String value)
    typeSpec.addMethod(MethodSpec.methodBuilder("of").addAnnotation(JsonCreator.class).addModifiers(Modifier.PUBLIC, Modifier.STATIC).addParameter(String.class, "name").returns(self)
        .addStatement("return $N.get($N)", staticNameMap, "name").build());

    LOG.info("Buit Pojo Class");
  }

  private MethodSpec.Builder ctorUsingFields(FieldSpec... fieldSpecs) {
    MethodSpec.Builder ctor = MethodSpec.constructorBuilder().addModifiers(Modifier.PRIVATE);
    for (FieldSpec fieldspec : fieldSpecs) {
      ctor.addParameter(fieldspec.type, fieldspec.name).addStatement("this.$N = $N", fieldspec, fieldspec);
    }
    return ctor;
  }

  private List<MethodSpec> generateGetter(FieldSpec... fieldSpecs) {
    List<MethodSpec> retVal = new ArrayList<MethodSpec>();
    for (FieldSpec fieldspec : fieldSpecs) {
      String prefix = "get";
      if (fieldspec.type.equals(TypeName.BOOLEAN)) {
        prefix = "is";
      }
      retVal.add(MethodSpec.methodBuilder(StringUtils.join(prefix, StringUtils.capitalize(fieldspec.name))).addModifiers(Modifier.PUBLIC).returns(fieldspec.type)
          .addStatement("return this.$N", fieldspec).build());
    }
    return retVal;
  }

  @Override
  protected void afterTest() throws Exception {
    ClassName assertEquals = ClassName.get("org.junit.jupiter.api", "Assertions", "assertEquals");
    testSpec.addMethod(MethodSpec.methodBuilder("testGet").addAnnotation(ClassName.get("org.junit.jupiter.api", "Test")).addModifiers(Modifier.PUBLIC).addException(Exception.class)
        .addStatement("$R($T.TLS_NULL_WITH_NULL_NULL, $T.of($L))", assertEquals, self, self, 0x0000).build());

  }

}
