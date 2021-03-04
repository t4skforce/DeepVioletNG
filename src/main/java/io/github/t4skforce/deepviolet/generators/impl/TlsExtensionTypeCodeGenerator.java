package io.github.t4skforce.deepviolet.generators.impl;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;

import io.github.t4skforce.deepviolet.protocol.tls.exception.TlsProtocolException;
import io.github.t4skforce.deepviolet.protocol.tls.util.TlsUtils;

import java.util.HashMap;
import java.util.Map;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;

public class TlsExtensionTypeCodeGenerator extends HttpRequestCodeGenerator {

  private static final FieldSpec STATIC_RESERVED = FieldSpec.builder(String.class, "RESERVED", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "reserved").build();

  private static final FieldSpec STATIC_UNASSIGNED = FieldSpec.builder(String.class, "UNASSIGNED", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL).initializer("$S", "unassigned").build();

  private static final FieldSpec STATIC_RESERVED_FOR_PRIVATE_USE = FieldSpec.builder(String.class, "RESERVED_FOR_PRIVATE_USE", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
      .initializer("$S", "reserved_for_private_use").build();

  private static final String TARGET_CLASS_NAME = "io.github.t4skforce.deepviolet.protocol.tls.extension.TlsExtensionTypeGenerated";

  private static final String SOURCE_URL = "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml";

  public TlsExtensionTypeCodeGenerator() throws Exception {
    super();
  }

  @Override
  public String getTargetCanonicalName() {
    return TARGET_CLASS_NAME;
  }

  @Override
  protected HttpRequestBase getRequest() {
    return new HttpGet(SOURCE_URL);
  }

  private void parseResponse(CloseableHttpResponse response, FieldSpec staticLookup, CodeBlock.Builder lookupInit) {
    // TODO: implement
    // https://www.baeldung.com/java-xpath
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
    String buffName = "buff";
    typeSpec.addMethod(MethodSpec.methodBuilder("of").addModifiers(Modifier.PUBLIC, Modifier.STATIC).returns(self).addParameter(byte[].class, buffName).addException(TlsProtocolException.class)
        .addJavadoc("Returns instance of {@link $T} for given protocol bytes\n@param $N\n@return\n@throws $T", self, buffName, TlsProtocolException.class)
        .beginControlFlow("if ($T.isNotEmpty($N) && $N.length == 2)", ArrayUtils.class, buffName, buffName).addStatement("int $N = $T.dec16be($N)", "key", TlsUtils.class, buffName)
        .beginControlFlow("if ($N.containsKey($N))", staticLookup, "key").addStatement("return $N.get($N)", staticLookup, "key").endControlFlow().endControlFlow()
        .addStatement("throw new $T($S + $T.toString($N) + $S)", TlsProtocolException.class, "Given data [", TlsUtils.class, buffName, "] is invalid for ExtensionType").build());

    // toString()
    MethodSpec toString = MethodSpec.methodBuilder("toString").addModifiers(Modifier.PUBLIC).returns(String.class).addAnnotation(Override.class).addStatement("return $N", name).build();
    typeSpec.addMethod(toString);

    // hashCode()
    MethodSpec hashCode = MethodSpec.methodBuilder("hashCode").addModifiers(Modifier.PUBLIC).returns(TypeName.INT).addAnnotation(Override.class).addStatement("return $N", value).build();
    typeSpec.addMethod(hashCode);

    // equals(Object obj)
    MethodSpec equals = MethodSpec.methodBuilder("equals").addModifiers(Modifier.PUBLIC).returns(TypeName.BOOLEAN).addParameter(Object.class, "obj").addAnnotation(Override.class)
        .beginControlFlow("if (this == obj)").addStatement("return true").endControlFlow().beginControlFlow("if (obj == null || getClass() != obj.getClass())").addStatement("return false")
        .endControlFlow().addStatement("return $N != (($N) $N).$N", value, self.simpleName(), "obj", value).build();
    typeSpec.addMethod(equals);

  }

}
