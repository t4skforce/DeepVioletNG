package io.github.t4skforce.deepviolet.generators.impl;

import java.util.List;

import org.apache.http.client.methods.HttpRequestBase;

public abstract class HttpRequestCodeGenerator extends MultiHttpRequestCodeGenerator {

  protected HttpRequestCodeGenerator() throws Exception {
    super();
  }

  @Override
  protected List<ResponseProcessor> getProcessors() {
    return ResponseProcessor.builder().request(this::getRequest, this::process).build();
  }

  protected abstract HttpRequestBase getRequest();

  protected abstract void process(String body) throws Exception;
}
