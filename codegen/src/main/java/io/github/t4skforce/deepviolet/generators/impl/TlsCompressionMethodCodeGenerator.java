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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;

// https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml
public class TlsCompressionMethodCodeGenerator extends HttpRequestCodeGenerator {

  private static final String NAME_RESERVED = "RESERVED";

  private static final String NAME_UNASSIGNED = "UNASSIGNED";

  private static final String NAME_FORMAT = "%s:(0x%04X)";

  private static final String TARGET_CLASS_NAME = "io.github.t4skforce.deepviolet.jackson.dataformat.tls.model.record.handshake.CompressionMethod";

  private static final String SOURCE_URL = "https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml";

  public TlsCompressionMethodCodeGenerator() throws Exception {
    super();
  }

  @Override
  protected String getClassName() {
    return TARGET_CLASS_NAME;
  }

  @Override
  protected HttpRequestBase getRequest() {
    return new HttpGet(SOURCE_URL);
  }

  private List<TlsCompressionMethodWrapper> compressions = new ArrayList<>();

  private class TlsCompressionMethodWrapper implements Comparable<TlsCompressionMethodWrapper> {
    protected int from;
    protected int to;
    protected String name = StringUtils.EMPTY;
    protected List<String> refs = new ArrayList<>();

    public TlsCompressionMethodWrapper(int from, int to, String name, List<String> refs) {
      this.from = from;
      this.to = to;
      this.name = name;
      this.refs = refs;
    }

    public TlsCompressionMethodWrapper(int from, String name, List<String> refs) {
      this(from, from, name, refs);
    }

    public boolean isRange() {
      return from < to;
    }

    public boolean isUnassigned() {
      return StringUtils.startsWithIgnoreCase(name, "Unassigned");
    }

    public boolean isReserved() {
      return StringUtils.startsWithIgnoreCase(name, "Reserved");
    }

    @Override
    public int compareTo(TlsCompressionMethodWrapper o) {
      return Integer.valueOf(this.from).compareTo(Integer.valueOf(o.from));
    }
  }

  @Override
  protected void process(String response) throws Exception {
    HtmlUtils.elems(response, "#table-comp-meth-ids-2 tbody tr").orElseThrow(() -> {
      return new IOException("Could not find Iana data");
    }).forEach(elem -> {
      String value = elem.select("td:eq(0)").first().text();
      String description = elem.select("td:eq(1)").first().text();
      List<String> refs = elem.select("td:eq(2) a").stream().map(e -> e.outerHtml()).collect(Collectors.toList());
      Boolean isRanged = StringUtils.contains(value, '-');
      Integer from = null;
      Integer to = null;
      if (isRanged) {
        String[] pts = StringUtils.split(value, '-');
        from = Integer.parseUnsignedInt(pts[0]);
        to = Integer.parseUnsignedInt(pts[1]);
        compressions.add(new TlsCompressionMethodWrapper(from, to, description, refs));
      } else {
        from = Integer.parseUnsignedInt(value);
        compressions.add(new TlsCompressionMethodWrapper(from, description, refs));
      }
    });
  }

  @Override
  protected void after() throws Exception {
    typeSpec.addJavadoc("<br/>This class is based on <a href=$S>www.iana.org</a> specification", SOURCE_URL);
    typeSpec.addAnnotation(AnnotationSpec.builder(ClassName.get("io.github.t4skforce.deepviolet.jackson.dataformat.tls.annotations", "TlsCompressionMethod")).build());

    // static strings
    FieldSpec staticNameFormat = FieldSpec.builder(String.class, "NAME_FORMAT", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_FORMAT).build();
    typeSpec.addField(staticNameFormat);
    FieldSpec staticUnassigned = FieldSpec.builder(String.class, NAME_UNASSIGNED, Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_UNASSIGNED).build();
    typeSpec.addField(staticUnassigned);
    FieldSpec staticReserved = FieldSpec.builder(String.class, NAME_RESERVED, Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", NAME_RESERVED).build();
    typeSpec.addField(staticReserved);

    // static lookup section
    FieldSpec staticValueMap = FieldSpec
        .builder(ParameterizedTypeName.get(ClassName.get(Map.class), ClassName.get(Integer.class), self), "VALUE_MAP", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
        .initializer("new $T<>()", HashMap.class).build();
    FieldSpec staticNameMap = FieldSpec.builder(ParameterizedTypeName.get(ClassName.get(Map.class), ClassName.get(String.class), self), "NAME_MAP", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
        .initializer("new $T<>()", HashMap.class).build();

    // Generate static instance fields
    CodeBlock.Builder lookupInit = CodeBlock.builder();
    List<FieldSpec> staticFields = new ArrayList<>();

    for (TlsCompressionMethodWrapper compression : compressions) {
      if (compression.isRange()) {
        lookupInit.add(CodeBlock.builder().beginControlFlow("for (int i = $L; i <= $L; i++)", String.format("0x%02X", compression.from), String.format("0x%02X", compression.to))
            .addStatement("new $T(i, $S, $L, $L)", self, compression.name, compression.isUnassigned(), compression.isReserved()).endControlFlow().build());
      } else {
        FieldSpec staticField = FieldSpec.builder(self, compression.name.toUpperCase(), Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL)
            .addJavadoc("Static variable for $N compression.<br/>\n<strong>References:</strong> $L", compression.name, StringUtils.join(compression.refs, ", "))
            .initializer(CodeBlock.of("new $T($N, $S, $L, $L)", self, String.format("0x%02X", compression.from), compression.name, compression.isUnassigned(), compression.isReserved())).build();
        staticFields.add(staticField);
      }
    }

    typeSpec.addField(staticValueMap);
    typeSpec.addField(staticNameMap);
    typeSpec.addFields(staticFields);
    typeSpec.addStaticBlock(lookupInit.build());

    FieldSpec value = FieldSpec.builder(TypeName.INT, "value", Modifier.PRIVATE).build();
    FieldSpec name = FieldSpec.builder(String.class, "name", Modifier.PRIVATE).build();
    FieldSpec reserved = FieldSpec.builder(TypeName.BOOLEAN, "reserved", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    FieldSpec unassigned = FieldSpec.builder(TypeName.BOOLEAN, "unassigned", Modifier.PRIVATE).initializer("$L", Boolean.FALSE).build();
    typeSpec.addFields(Arrays.asList(value, name, reserved, unassigned));

    MethodSpec getName = MethodSpec.methodBuilder("getName").addModifiers(Modifier.PUBLIC).returns(String.class).addAnnotation(JsonValue.class).beginControlFlow("if (this.$N)", unassigned)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticUnassigned, value).nextControlFlow("else if (this.$N)", reserved)
        .addStatement("return $T.format($N, $N, this.$N)", String.class, staticNameFormat, staticReserved, value).nextControlFlow("else").addStatement("return this.$N", name).endControlFlow().build();
    CodeBlock addToLookupCodeBlock = CodeBlock.builder().addStatement("$N.put(this.$N(), this)", staticNameMap, getName).addStatement("$N.put(this.$N, this)", staticValueMap, value).build();
    MethodSpec.Builder ctor = JavaPoetUtils.privateConstructor(value, name, reserved, unassigned).addCode(addToLookupCodeBlock);
    typeSpec.addMethod(ctor.build());

    // generate public getter in pojo
    typeSpec.addMethods(JavaPoetUtils.getter(value));

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

  }

  @Override
  protected void afterTest() throws Exception {
    for (TlsCompressionMethodWrapper compression : compressions) {
      if (!compression.isRange()) {
        testSpec.addMethod(JavaPoetUtils.test(compression.name.toLowerCase()).addStatement("$T compression = $T.$L", self, self, compression.name)
            .addStatement("$T($S, compression.getName())", assertEquals, compression.name).addStatement("$T($L, compression.getValue())", assertEquals, String.format("0x%02X", compression.from))
            .addStatement("$T(compression, $T.of($N))", assertEquals, self, String.format("0x%02X", compression.from)).addStatement("$T(compression, $T.of($S))", assertEquals, self, compression.name)
            .build());
      }
    }

    CodeBlock.Builder cb = CodeBlock.builder();
    cb.beginControlFlow("for (int i=0x00; i<=0xFF; i++)").addStatement("$T($T.of(i), $T.format($S, i))", assertNotNull, self, String.class, self.simpleName() + ".of(0x%02X)")
        .addStatement("$T($T.of(i) == $T.of(i))", assertTrue, self, self).addStatement("$T($T.of(i) == $T.of($T.of(i).getName()))", assertTrue, self, self, self)
        .addStatement("$T($T.of($T.of(i).toString()) == $T.of($T.of(i).getName()))", assertTrue, self, self, self, self).endControlFlow();
    testSpec.addMethod(JavaPoetUtils.test("testFullRange").addCode(cb.build()).build());
  }

}
