package io.github.t4skforce.deepviolet.test.extension;

import com.google.common.io.Resources;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("restriction")
public class SimpleHttpsServer {

  private static final Logger LOG = LoggerFactory.getLogger(SimpleHttpsServer.class);

  private HttpServer httpsServer;

  private String[] protocols;

  private String[] suites;

  private boolean isHttps;

  protected ExecutorService executor = Executors.newFixedThreadPool(10);

  public static final HttpHandler NOT_FOUND_HANDLER = new NotFoundHttpHandler();

  public SimpleHttpsServer(String hostAddress, int port, String[] protocols, String[] suites,
      InputStream keyStore, String keyStorePassword, String keyPassword, InputStream trustStore,
      String trustStorePassword, HttpHandler defaultHandler) throws Exception {

    // setup the socket address
    InetSocketAddress address = new InetSocketAddress(hostAddress, port);

    this.isHttps = Objects.nonNull(keyStore);

    if (this.isHttps) {
      Security.setProperty("crypto.policy", "unlimited");
      Security.setProperty("jdk.certpath.disabledAlgorithms", "");
      Security.setProperty("jdk.tls.disabledAlgorithms", "");

      // initialise the HTTPS server
      httpsServer = (HttpServer) HttpsServer.create(address, 0);

      // setup the HTTPS context and parameters
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(createKeyManagers(keyStore, keyStorePassword, keyPassword),
          createTrustManagers(trustStore, trustStorePassword), new SecureRandom());

      SSLEngine engine = sslContext.createSSLEngine();
      this.protocols = protocols;
      if (ArrayUtils.isEmpty(this.protocols)) {
        this.protocols = engine.getSupportedProtocols();
      }
      Arrays.sort(this.protocols);
      // System.out.println(StringUtils.join(this.protocols, "\n"));

      this.suites = suites;
      if (ArrayUtils.isEmpty(this.suites)) {
        this.suites = engine.getSupportedCipherSuites();
      }
      Arrays.sort(this.suites);
      // System.out.println(StringUtils.join(this.suites, "\n"));

      configure(sslContext, this.protocols, this.suites);
    } else {
      httpsServer = HttpServer.create(address, 0);
    }

    httpsServer.setExecutor(executor);

    // setup routing
    if (defaultHandler != null) {
      addRoute("/", defaultHandler);
    } else {
      addRoute("/", NOT_FOUND_HANDLER);
    }

  }

  private void configure(SSLContext sslContext, String[] protocols, String[] suites) {
    ((HttpsServer) httpsServer).setHttpsConfigurator(new HttpsConfigurator(sslContext) {
      public void configure(HttpsParameters params) {
        try {

          // initialise the SSL context
          params.setNeedClientAuth(false);
          params.setCipherSuites(suites);
          params.setProtocols(protocols);
          // get the default parameters
          SSLParameters defaultSSLParameters = sslContext.getDefaultSSLParameters();
          defaultSSLParameters.setNeedClientAuth(false);
          defaultSSLParameters.setCipherSuites(suites);
          defaultSSLParameters.setProtocols(protocols);

          params.setSSLParameters(defaultSSLParameters);

        } catch (Exception ex) {
          LOG.error("Failed to create HTTPS port", ex);
        }
      }
    });
  }

  public void addRoute(String path, HttpHandler handler) {
    httpsServer.createContext(path, handler);
  }

  public void addRoute(String path, Class<HttpHandler> handler) throws Exception {
    addRoute(path, handler.getDeclaredConstructor().newInstance());
  }

  public void removeRoute(String path) {
    httpsServer.removeContext(path);
  }

  public void start() {
    httpsServer.start();
  }

  public void stop(int delay) {
    httpsServer.stop(delay);
  }

  public int getPort() {
    return httpsServer.getAddress().getPort();
  }

  public String getHostName() {
    return httpsServer.getAddress().getHostString();
  }

  public String[] getProtocols() {
    return this.protocols;
  }

  public String[] getCypherSuites() {
    return this.suites;
  }

  public URI getUri() {
    if (this.isHttps) {
      if (getPort() == 443) {
        return URI.create("https://" + getHostName());
      }
      return URI.create("https://" + getHostName() + ":" + getPort());
    } else {
      if (getPort() == 80) {
        return URI.create("http://" + getHostName());
      }
      return URI.create("http://" + getHostName() + ":" + getPort());
    }
  }

  public boolean isHttps() {
    return isHttps;
  }

  public static SimpleHttpsServerExtension extension() {
    return new SimpleHttpsServerExtension();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class SimpleHttpsServerExtension
      implements BeforeEachCallback, AfterEachCallback, ParameterResolver {

    private SimpleHttpsServer server;

    private SimpleHttpsServerExtension() {
      super();
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
      SimpleHttpsServerConfig config = context.getTestMethod()
          .filter(m -> m.isAnnotationPresent(SimpleHttpsServerConfig.class))
          .map(m -> m.getAnnotation(SimpleHttpsServerConfig.class)).orElseGet(null);
      if (Objects.nonNull(config)) {
        server = setup(config);
        server.start();
      }
    }

    private SimpleHttpsServer setup(SimpleHttpsServerConfig config) throws Exception {
      Builder builder = SimpleHttpsServer.builder();

      if (StringUtils.isNoneBlank(config.host())) {
        builder.host(config.host());
      }
      builder.port(config.port());

      KeyStore key = config.key();
      if (StringUtils.isNotEmpty(key.value())) {
        builder.keyStore(key.value());
        if (StringUtils.isNoneBlank(key.store())) {
          builder.keyStorePassword(key.store());
        }
        if (StringUtils.isNoneBlank(key.key())) {
          builder.keyStoreKeyPassword(key.key());
        }
      }

      TrustStore trust = config.trust();
      if (StringUtils.isNoneBlank(trust.value())) {
        builder.trustStore(trust.value());
        if (StringUtils.isNoneBlank(trust.pass())) {
          builder.trustStorePassword(trust.pass());
        }
      }

      // protocols
      builder.protocols(config.protocols());

      // ciphersuites
      builder.suites(config.ciphers());

      // routing setup
      builder.defaultRoute(config.defaultRoute());

      RequestHandler[] routes = config.routes();
      if (ArrayUtils.isNotEmpty(routes)) {
        for (RequestHandler route : routes) {
          builder.route(route.value(), route.handler());
        }
      }

      return builder.build();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
      if (server != null) {
        server.stop(1);
      }
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext,
        ExtensionContext extensionContext) throws ParameterResolutionException {
      return parameterContext.getParameter().getType() == SimpleHttpsServer.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext,
        ExtensionContext extensionContext) throws ParameterResolutionException {
      return server;
    }

  }

  @Documented @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
  public @interface SimpleHttpsServerConfig {
    String host()

    default "localhost";

    int port()

    default 0;

    KeyStore key() default @KeyStore("");

    String[] protocols() default {};

    String[] ciphers() default {};

    TrustStore trust() default @TrustStore("");

    RequestHandler[] routes() default {};

    Class<? extends HttpHandler> defaultRoute() default NotFoundHttpHandler.class;
  }

  @Documented @Retention(RetentionPolicy.RUNTIME)
  public @interface KeyStore {
    String value();

    String store() default "";

    String key() default "";
  }

  @Documented @Retention(RetentionPolicy.RUNTIME)
  public @interface TrustStore {
    String value();

    String pass() default "";
  }

  @Documented @Retention(RetentionPolicy.RUNTIME)
  public @interface RequestHandler {
    String value();

    Class<? extends HttpHandler> handler();
  }

  private static class NotFoundHttpHandler implements HttpHandler {

    public NotFoundHttpHandler() {
    }

    @Override
    public void handle(HttpExchange t) throws IOException {
      t.getResponseHeaders().add("Content-Type", "text/html");
      String response = "<html><body><h1>Not Found</h1></body></html>";
      String conentType = t.getRequestHeaders()
          .getOrDefault("Content-Type", Arrays.asList("text/html")).get(0);
      if (StringUtils.endsWithIgnoreCase(conentType, "/json")) {
        t.getResponseHeaders().add("Content-Type", "application/json");
        response = "{\"error\":\"Not Found\"}";
      } else if (StringUtils.endsWithIgnoreCase(conentType, "/xml")
          || StringUtils.endsWithIgnoreCase(conentType, "/xhtml+xml")) {
        t.getResponseHeaders().add("Content-Type", "text/xml");
        response = "<response><error>Not Found</error></response>";
      }
      t.sendResponseHeaders(404, response.length());
      OutputStream os = t.getResponseBody();
      os.write(response.getBytes());
      os.close();
    }
  }

  public static class Builder {

    InputStream keyStore = null;
    InputStream trustStore = null;
    Set<String> protocol = new TreeSet<>();
    Set<String> suites = new TreeSet<>();
    String hostname = "localhost";
    int port = 0;
    String keyStorePassword = null;
    String keyPassword = null;
    String trustStorePassword = null;
    HttpHandler defaultRoute = null;
    Map<String, HttpHandler> routes = new TreeMap<>();

    private Builder() {
      String ts = System.getProperty("javax.net.ssl.trustStore", null);
      if (StringUtils.isNoneEmpty(ts)) {
        try {
          trustStore = new FileInputStream(ts);
        } catch (FileNotFoundException e) {
          // ignore
        }
      }
      trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", null);
    }

    public Builder protocols(String... protocol) {
      this.protocol = new TreeSet<>(Arrays.asList(protocol));
      return this;
    }

    public Builder suites(String... suites) {
      this.suites = new TreeSet<>(Arrays.asList(suites));
      return this;
    }

    public Builder host(String hostname) {
      this.hostname = hostname;
      return this;
    }

    public Builder port(int port) {
      if (port < 0) {
        throw new IllegalArgumentException("Port number cannot be less than 0");
      }
      this.port = port;
      return this;
    }

    public Builder keyStore(String resourceName) throws IOException {
      return keyStore(resourceName, null, null);
    }

    public Builder keyStore(String resourceName, String storePassword) throws IOException {
      return keyStore(resourceName, storePassword, null);
    }

    public Builder keyStore(String resourceName, String storePassword, String keyPassword)
        throws IOException {
      return keyStore(
          new ByteArrayInputStream(Resources.toByteArray(Resources.getResource(resourceName))),
          storePassword, keyPassword);
    }

    public Builder keyStore(InputStream keyStore) {
      return keyStore(keyStore, null, null);
    }

    public Builder keyStore(InputStream keyStore, String password) {
      return keyStore(keyStore, password, null);
    }

    public Builder keyStore(InputStream keyStore, String storePassword, String keyPassword) {
      this.keyStore = keyStore;
      this.keyStorePassword = storePassword;
      this.keyPassword = keyPassword;
      return this;
    }

    public Builder keyStorePassword(String password) {
      this.keyStorePassword = password;
      return this;
    }

    public Builder keyStoreKeyPassword(String password) {
      this.keyPassword = password;
      return this;
    }

    public Builder trustStore(String resourceName) throws IOException {
      return trustStore(resourceName, null);
    }

    public Builder trustStore(String resourceName, String password) throws IOException {
      return trustStore(
          new ByteArrayInputStream(Resources.toByteArray(Resources.getResource(resourceName))),
          password);
    }

    public Builder trustStore(InputStream trustStore) {
      return trustStore(trustStore, null);
    }

    public Builder trustStore(InputStream trustStore, String password) {
      this.trustStore = trustStore;
      this.trustStorePassword = password;
      return this;
    }

    public void trustStorePassword(String pass) {
      this.trustStorePassword = pass;
    }

    public void defaultRoute(Class<? extends HttpHandler> handler) throws Exception {
      defaultRoute(handler.getDeclaredConstructor().newInstance());
    }

    public void defaultRoute(HttpHandler handler) {
      this.defaultRoute = handler;
    }

    public void route(String path, Class<? extends HttpHandler> handler) throws Exception {
      route(path, handler.getDeclaredConstructor().newInstance());
    }

    public void route(String path, HttpHandler handler) {
      this.routes.put(path, handler);
    }

    public SimpleHttpsServer build() throws Exception {
      SimpleHttpsServer server = new SimpleHttpsServer(hostname, port,
          protocol.toArray(new String[] {}), suites.toArray(new String[] {}), keyStore,
          keyStorePassword, keyPassword, trustStore, trustStorePassword, defaultRoute);
      for (Entry<String, HttpHandler> route : this.routes.entrySet()) {
        server.addRoute(route.getKey(), route.getValue());
      }
      return server;
    }

  }

  private static java.security.KeyStore loadDefaultTrustStore() {
    Path location = null;
    String type = null;
    String password = null;

    String locationProperty = System.getProperty("javax.net.ssl.trustStore");
    if ((null != locationProperty) && (locationProperty.length() > 0)) {
      Path p = Paths.get(locationProperty);
      File f = p.toFile();
      if (f.exists() && f.isFile() && f.canRead()) {
        location = p;
      }
    } else {
      String javaHome = System.getProperty("java.home");
      location = Paths.get(javaHome, "lib", "security", "jssecacerts");
      if (!location.toFile().exists()) {
        location = Paths.get(javaHome, "lib", "security", "cacerts");
      }
    }

    String passwordProperty = System.getProperty("javax.net.ssl.trustStorePassword");
    if ((null != passwordProperty) && (passwordProperty.length() > 0)) {
      password = passwordProperty;
    } else {
      password = "changeit";
    }

    String typeProperty = System.getProperty("javax.net.ssl.trustStoreType");
    if ((null != typeProperty) && (typeProperty.length() > 0)) {
      type = passwordProperty;
    } else {
      type = java.security.KeyStore.getDefaultType();
    }

    java.security.KeyStore trustStore = null;
    try {
      trustStore = java.security.KeyStore.getInstance(type, Security.getProvider("SUN"));
    } catch (KeyStoreException e) {
      throw new RuntimeException(e);
    }

    try (InputStream is = Files.newInputStream(location)) {
      trustStore.load(is, password.toCharArray());
    } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    return trustStore;
  }

  /**
   * Creates the key managers required to initiate the {@link SSLContext}, using a JKS keystore as
   * an input.
   *
   * @param filepath - the path to the JKS keystore.
   * @param keystorePassword - the keystore's password.
   * @param keyPassword - the key's passsword.
   * @return {@link KeyManager} array that will be used to initiate the {@link SSLContext}.
   * @throws KeyStoreException
   * @throws IOException
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws UnrecoverableKeyException
   * @throws Exception
   */
  private static KeyManager[] createKeyManagers(InputStream file, String keystorePassword,
      String keyPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
      IOException, UnrecoverableKeyException {
    java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
    try (InputStream keyStoreFile = new BufferedInputStream(file)) {
      keyStore.load(keyStoreFile, keystorePassword.toCharArray());
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, keyPassword.toCharArray());
    return kmf.getKeyManagers();
  }

  /**
   * Creates the trust managers required to initiate the {@link SSLContext}, using a JKS keystore as
   * an input.
   *
   * @param filepath - the path to the JKS keystore.
   * @param keystorePassword - the keystore's password.
   * @return {@link TrustManager} array, that will be used to initiate the {@link SSLContext}.
   * @throws KeyStoreException
   * @throws IOException
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws Exception
   */
  private static TrustManager[] createTrustManagers(InputStream file, String keystorePassword)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    java.security.KeyStore trustStore;
    if (file == null) {
      trustStore = loadDefaultTrustStore();
    } else {
      trustStore = java.security.KeyStore.getInstance("JKS");
      try (InputStream keyStoreFile = new BufferedInputStream(file)) {
        trustStore.load(keyStoreFile, keystorePassword.toCharArray());
      }
    }
    TrustManagerFactory trustFactory = TrustManagerFactory
        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustFactory.init(trustStore);
    return trustFactory.getTrustManagers();
  }

}
