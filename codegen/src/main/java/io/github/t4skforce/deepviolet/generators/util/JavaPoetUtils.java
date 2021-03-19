package io.github.t4skforce.deepviolet.generators.util;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterSpec;
import com.squareup.javapoet.TypeName;

import java.util.ArrayList;
import java.util.List;

import javax.lang.model.element.Modifier;

import org.apache.commons.lang3.StringUtils;

public class JavaPoetUtils {

  public static final ClassName assertEquals = ClassName.get("org.junit.jupiter.api", "Assertions", "assertEquals");
  public static final ClassName assertTrue = ClassName.get("org.junit.jupiter.api", "Assertions", "assertTrue");
  public static final ClassName assertNotNull = ClassName.get("org.junit.jupiter.api", "Assertions", "assertNotNull");
  public static final ClassName testAnnotation = ClassName.get("org.junit.jupiter.api", "Test");

  public static MethodSpec.Builder privateConstructor(FieldSpec... fieldSpecs) {
    return constructor(Modifier.PRIVATE, fieldSpecs);
  }

  public static MethodSpec.Builder constructor(FieldSpec... fieldSpecs) {
    return constructor(Modifier.PUBLIC, fieldSpecs);
  }

  public static MethodSpec.Builder constructor(Modifier modifier, FieldSpec... fieldSpecs) {
    MethodSpec.Builder ctor = MethodSpec.constructorBuilder();
    for (FieldSpec fieldspec : fieldSpecs) {
      ctor.addParameter(fieldspec.type, fieldspec.name).addStatement("this.$N = $N", fieldspec, fieldspec).addModifiers(modifier);
    }
    return ctor;
  }

  public static List<MethodSpec> privateGetter(FieldSpec... fieldSpecs) {
    return getter(Modifier.PRIVATE, fieldSpecs);
  }

  public static List<MethodSpec> getter(FieldSpec... fieldSpecs) {
    return getter(Modifier.PUBLIC, fieldSpecs);
  }

  public static List<MethodSpec> getter(Modifier modifier, FieldSpec... fieldSpecs) {
    List<MethodSpec> retVal = new ArrayList<MethodSpec>();
    for (FieldSpec fieldspec : fieldSpecs) {
      String prefix = "get";
      if (fieldspec.type.equals(TypeName.BOOLEAN)) {
        prefix = "is";
      }
      retVal.add(
          MethodSpec.methodBuilder(StringUtils.join(prefix, StringUtils.capitalize(fieldspec.name))).addModifiers(modifier).returns(fieldspec.type).addStatement("return this.$N", fieldspec).build());
    }
    return retVal;
  }

  public static List<MethodSpec> privateSetter(FieldSpec... fieldSpecs) {
    return setter(Modifier.PRIVATE, fieldSpecs);
  }

  public static List<MethodSpec> setter(FieldSpec... fieldSpecs) {
    return setter(Modifier.PUBLIC, fieldSpecs);
  }

  public static List<MethodSpec> setter(Modifier modifier, FieldSpec... fieldSpecs) {
    List<MethodSpec> retVal = new ArrayList<MethodSpec>();
    for (FieldSpec fieldspec : fieldSpecs) {
      ParameterSpec param = ParameterSpec.builder(fieldspec.type, fieldspec.name).addModifiers(Modifier.FINAL).build();
      retVal.add(
          MethodSpec.methodBuilder(StringUtils.join("set", StringUtils.capitalize(fieldspec.name))).addParameter(param).addModifiers(modifier).addStatement("this.$N = $N", fieldspec, param).build());
    }
    return retVal;
  }

  public static MethodSpec.Builder test(String name) {
    return MethodSpec.methodBuilder(StringUtils.join("test", StringUtils.capitalize(name))).addAnnotation(testAnnotation).addModifiers(Modifier.PUBLIC).addException(Exception.class);
  }

}
