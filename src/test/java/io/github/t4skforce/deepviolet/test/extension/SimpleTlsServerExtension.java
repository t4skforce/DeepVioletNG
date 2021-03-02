package io.github.t4skforce.deepviolet.test.extension;

import io.github.t4skforce.deepviolet.protocol.tls.server.SimpleTlsServer;
import io.github.t4skforce.deepviolet.protocol.tls.server.SimpleTlsServer.Builder;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.impl.DefaultTlsErrorHandler;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.collections4.CollectionUtils;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleTlsServerExtension
    implements BeforeEachCallback, AfterEachCallback, ParameterResolver {

  private static final Logger LOG = LoggerFactory.getLogger(SimpleTlsServerExtension.class);

  private ExecutorService executor = Executors.newSingleThreadExecutor();

  private SimpleTlsServer server;

  private AssertationExceptionHandler errorHandler = new AssertationExceptionHandler();

  public SimpleTlsServerExtension() {
    super();
  }

  public static SimpleTlsServerExtension extension() {
    return new SimpleTlsServerExtension();
  }

  @Override
  public boolean supportsParameter(ParameterContext parameterContext,
      ExtensionContext extensionContext) throws ParameterResolutionException {
    return parameterContext.getParameter().getType() == SimpleTlsServer.class;
  }

  @Override
  public Object resolveParameter(ParameterContext parameterContext,
      ExtensionContext extensionContext) throws ParameterResolutionException {
    return server;
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    if (server != null) {
      server.stop();
    }
    this.executor.shutdownNow();
    if (CollectionUtils.isNotEmpty(errorHandler.getAssertionError())) {
      throw errorHandler.getAssertionError().get(0);
    }
  }

  private class AssertationExceptionHandler extends DefaultTlsErrorHandler {
    private List<AssertionError> errors = new ArrayList<>();

    @Override
    public void handle(AssertionError error) {
      errors.add(error);
    }

    @Override
    public void handle(Throwable throwable) {
      LOG.error(throwable.getMessage(), throwable);
    }

    public List<AssertionError> getAssertionError() {
      return errors;
    }
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    Optional<SimpleTlsServerConfig> config = context.getTestMethod()
        .filter(m -> m.isAnnotationPresent(SimpleTlsServerConfig.class))
        .map(m -> m.getAnnotation(SimpleTlsServerConfig.class));
    if (config.isPresent()) {
      SimpleTlsServerConfig cfg = config.get();
      Builder builder = SimpleTlsServer.builder().host(cfg.host()).port(cfg.port())
          .handler(errorHandler);
      this.server = builder.build();
      executor.submit(this.server);
    }
  }

  @Documented @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
  public @interface SimpleTlsServerConfig {
    String host()

    default "localhost";

    int port() default 0;
  }

}
