package io.github.t4skforce.deepviolet.test.extension;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class TLSServerExtension implements BeforeAllCallback, AfterAllCallback {

  private ExecutorService serverExecutor = Executors.newFixedThreadPool(10);

  private TLSServerExtension() {
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    public Builder enableSecurity(boolean b) {
      return this;
    }

    public TLSServerExtension build() {
      return new TLSServerExtension();
    }

  }

  private void serve() {

  }

  @Override
  public void afterAll(ExtensionContext context) throws Exception {
    if (!serverExecutor.isShutdown() && !serverExecutor.isTerminated()) {
      serverExecutor.shutdownNow();
    }
  }

  @Override
  public void beforeAll(ExtensionContext context) throws Exception {

  }

}
