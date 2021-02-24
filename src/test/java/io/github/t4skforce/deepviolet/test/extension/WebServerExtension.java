package io.github.t4skforce.deepviolet.test.extension;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class WebServerExtension implements BeforeAllCallback, AfterAllCallback {

  private WebServerExtension() {
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    public Builder enableSecurity(boolean b) {
      return this;
    }

    public WebServerExtension build() {
      return new WebServerExtension();
    }

  }

  @Override
  public void afterAll(ExtensionContext context) throws Exception {
    // TODO Auto-generated method stub

  }

  @Override
  public void beforeAll(ExtensionContext context) throws Exception {
    // TODO Auto-generated method stub

  }

}
