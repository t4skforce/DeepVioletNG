package io.github.t4skforce.deepviolet.generators.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvParser;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;

import io.github.t4skforce.deepviolet.generators.mapper.deserializer.BooleanDeserializer;
import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;

public class TlsExtensionTypeCodeGenerator extends HttpRequestCodeGenerator {

  private static final FieldSpec STATIC_RESERVED = FieldSpec.builder(String.class, "RESERVED", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "reserved").build();

  private static final FieldSpec STATIC_UNASSIGNED = FieldSpec.builder(String.class, "UNASSIGNED", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "unassigned").build();

  private static final FieldSpec STATIC_RESERVED_FOR_PRIVATE_USE = FieldSpec.builder(String.class, "RESERVED_FOR_PRIVATE_USE", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
      .initializer("$S", "reserved_for_private_use").build();

  private static final String TARGET_CLASS_NAME = "io.github.t4skforce.deepviolet.protocol.tls.extension.TlsExtensionTypeGenerated";

  private static final String SOURCE_URL = "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv";

  public TlsExtensionTypeCodeGenerator() throws Exception {
    super();
    setCacheMaxAgeUnit(TimeUnit.DAYS);
    setCacheMaxAgeValue(1);
  }

  @Override
  public String getTargetCanonicalName() {
    return TARGET_CLASS_NAME;
  }

  @Override
  protected HttpRequestBase getRequest() {
    return new HttpGet(SOURCE_URL);
  }

  @JsonPropertyOrder({ "Value", "Extension Name", "TLS 1.3", "Recommended", "Reference" })
  static class TlsExtensionTypeLine {

    @JsonProperty("Extension Name")
    private String name;

    @JsonProperty("TLS 1.3")
    private String tls13;

    @JsonProperty("Recommended")
    @JsonDeserialize(using = BooleanDeserializer.class)
    private Boolean recommended;

    @JsonProperty("Reference")
    private String references;

    @JsonIgnore
    private boolean range;

    @JsonIgnore
    private Integer to;

    @JsonIgnore
    private Integer from;

    public TlsExtensionTypeLine() {
      super();
    }

    public String getValue() {
      if (this.range) {
        return String.format("%s-%s", this.from, this.to);
      }
      return this.from != null ? this.from.toString() : StringUtils.EMPTY;
    }

    @JsonProperty("Value")
    public void setValue(String value) {
      if (StringUtils.isNoneBlank(value)) {
        String[] parts = StringUtils.split(value, "-");
        this.range = parts.length == 2;
        this.to = this.from = Integer.valueOf(parts[0]);
        if (this.range) {
          this.to = Integer.valueOf(parts[1]);
        }
      }
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getTls13() {
      return tls13;
    }

    public void setTls13(String tls13) {
      this.tls13 = tls13;
    }

    public Boolean getRecommended() {
      return recommended;
    }

    public void setRecommended(Boolean recommended) {
      this.recommended = recommended;
    }

    public String getReferences() {
      return references;
    }

    public void setReferences(String references) {
      this.references = references;
    }

    public boolean isRange() {
      return range;
    }

    public void setRange(boolean range) {
      this.range = range;
    }

    public Integer getTo() {
      return to;
    }

    public void setTo(Integer to) {
      this.to = to;
    }

    public Integer getFrom() {
      return from;
    }

    public void setFrom(Integer from) {
      this.from = from;
    }

    @Override
    public String toString() {
      return "TlsExtensionTypeLine [value=" + getValue() + ", name=" + name + ", tls13=" + tls13 + ", recommended=" + recommended + ", references=" + references + "]";
    }
  }

  private void parseResponse(CloseableHttpResponse response, FieldSpec staticLookup, CodeBlock.Builder lookupInit) {
    // TODO: implement
    // https://www.baeldung.com/java-xpath
    CsvMapper mapper = CsvMapper.builder().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false).enable(CsvParser.Feature.TRIM_SPACES).enable(CsvParser.Feature.SKIP_EMPTY_LINES)
        .enable(CsvParser.Feature.IGNORE_TRAILING_UNMAPPABLE).enable(CsvParser.Feature.TRIM_SPACES).build();
    CsvSchema schema = mapper.schemaFor(TlsExtensionTypeLine.class).withHeader();

    try {
      MappingIterator<TlsExtensionTypeLine> typeLines = mapper.readerFor(TlsExtensionTypeLine.class).with(schema).readValues(response.getEntity().getContent());
      for (TlsExtensionTypeLine line : typeLines.readAll()) {
        System.out.println(line);
      }
    } catch (UnsupportedOperationException | IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  @Override
  protected void doBuild(CloseableHttpResponse response) {
    typeSpec.addJavadoc("<br/>based on <a href=$S>www.iana.org</a> specification", SOURCE_URL);

    // private static fields
    typeSpec.addField(STATIC_RESERVED_FOR_PRIVATE_USE);
    typeSpec.addField(STATIC_UNASSIGNED);
    typeSpec.addField(STATIC_RESERVED);

    // public static fields
    FieldSpec staticLookup = FieldSpec.builder(ParameterizedTypeName.get(ClassName.get(Map.class), ClassName.get(Integer.class), self), "LOOKUP", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
        .initializer("new $T<>()", HashMap.class).build();
    CodeBlock.Builder lookupInit = CodeBlock.builder();
    parseResponse(response, staticLookup, lookupInit);
    typeSpec.addField(staticLookup);
    typeSpec.addStaticBlock(lookupInit.build());

    // private fields
    FieldSpec value = FieldSpec.builder(TypeName.INT, "value", Modifier.PRIVATE).build();
    FieldSpec name = FieldSpec.builder(String.class, "name", Modifier.PRIVATE).build();
    FieldSpec recommended = FieldSpec.builder(TypeName.BOOLEAN, "recommended", Modifier.PRIVATE).build();
    typeSpec.addField(value).addField(name).addField(recommended);

    // empty constructor
    typeSpec.addMethod(MethodSpec.constructorBuilder().addModifiers(Modifier.PRIVATE).addStatement("super()").build());

    // type constructor
    MethodSpec ctor = MethodSpec.constructorBuilder().addModifiers(Modifier.PRIVATE).addParameter(TypeName.INT, value.name).addParameter(String.class, name.name)
        .addParameter(TypeName.BOOLEAN, recommended.name).addStatement("this.$N = $N", value, value).addStatement("this.$N = $N", name, name).addStatement("this.$N = $N", recommended, recommended)
        .build();
    typeSpec.addMethod(ctor);

    // getValue()
    MethodSpec getValue = MethodSpec.methodBuilder("getValue").addModifiers(Modifier.PUBLIC).returns(TypeName.INT).addStatement("return $N", value).build();
    typeSpec.addMethod(getValue);

    // getBytes()
    MethodSpec getBytes = MethodSpec.methodBuilder("getBytes").addModifiers(Modifier.PUBLIC).returns(byte[].class).addStatement("return $T.enc16be($N, new byte[2])", TlsUtils.class, value).build();
    typeSpec.addMethod(getBytes);

    // getName()
    MethodSpec getName = MethodSpec.methodBuilder("getName").addModifiers(Modifier.PUBLIC).returns(String.class).addStatement("return $N", name).build();
    typeSpec.addMethod(getName);

    // isRecommended()
    MethodSpec isRecommended = MethodSpec.methodBuilder("isRecommended").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN).addStatement("return $N", recommended).build();
    typeSpec.addMethod(isRecommended);

    // isReserved()
    MethodSpec isReserved = MethodSpec.methodBuilder("isReserved").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN).addStatement("return $N.equals($N)", STATIC_RESERVED, name).build();
    typeSpec.addMethod(isReserved);

    // isUnassigned()
    MethodSpec isUnassigned = MethodSpec.methodBuilder("isUnassigned").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN).addStatement("return $N.equals($N)", STATIC_UNASSIGNED, name).build();
    typeSpec.addMethod(isUnassigned);

    // isReserved()
    MethodSpec isReservedForPrivateUse = MethodSpec.methodBuilder("isReservedForPrivateUse").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN)
        .addStatement("return $N.equals(this.$N)", STATIC_RESERVED_FOR_PRIVATE_USE, name).build();
    typeSpec.addMethod(isReservedForPrivateUse);

    // isValid()
    MethodSpec isValid = MethodSpec.methodBuilder("isValid").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN)
        .addStatement("return !$N() && !$N() && !$N()", isReserved, isUnassigned, isReservedForPrivateUse).build();
    typeSpec.addMethod(isValid);

    // of(byte[] buff)
    ParameterSpec buffParam = ParameterSpec.builder(byte[].class, "buff").build();
    MethodSpec of = MethodSpec.methodBuilder("of").addModifiers(Modifier.PUBLIC, Modifier.STATIC).returns(self).addParameter(buffParam).addException(TlsProtocolException.class)
        .addJavadoc("Returns instance of {@link $T} for given protocol bytes\n@param $N\n@return\n@throws $T", self, buffParam, TlsProtocolException.class)
        .beginControlFlow("if ($T.isNotEmpty($N) && $N.length == 2)", ArrayUtils.class, buffParam, buffParam).addStatement("int $N = $T.dec16be($N)", "key", TlsUtils.class, buffParam)
        .beginControlFlow("if ($N.containsKey($N))", staticLookup, "key").addStatement("return $N.get($N)", staticLookup, "key").endControlFlow().endControlFlow()
        .addStatement("throw new $T($S + $T.toString($N) + $S)", TlsProtocolException.class, "Given data [", TlsUtils.class, buffParam, "] is invalid for ExtensionType").build();
    typeSpec.addMethod(of);

    // toString()
    MethodSpec toString = MethodSpec.methodBuilder("toString").addModifiers(Modifier.PUBLIC).returns(String.class).addAnnotation(Override.class).addStatement("return $N", name).build();
    typeSpec.addMethod(toString);

    // hashCode()
    MethodSpec hashCode = MethodSpec.methodBuilder("hashCode").addModifiers(Modifier.PUBLIC).returns(TypeName.INT).addAnnotation(Override.class).addStatement("return $N", value).build();
    typeSpec.addMethod(hashCode);

    // equals(Object obj)
    ParameterSpec objParam = ParameterSpec.builder(Object.class, "obj").build();
    MethodSpec equals = MethodSpec.methodBuilder("equals").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN).addParameter(objParam).addAnnotation(Override.class)
        .beginControlFlow("if (this == $N)", objParam).addStatement("return true").endControlFlow().beginControlFlow("if ($N == null || getClass() != $N.getClass())", objParam, objParam)
        .addStatement("return false").endControlFlow().addStatement("return $N != (($N) $N).$N", value, self.simpleName(), objParam, value).build();
    typeSpec.addMethod(equals);

  }

}
