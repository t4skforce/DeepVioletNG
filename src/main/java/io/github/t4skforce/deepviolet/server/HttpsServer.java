package io.github.t4skforce.deepviolet.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpsServer {

  private static final Logger LOG = LoggerFactory.getLogger(HttpsServer.class);

  private TlsServer tlsServer;

  private HttpsServer(TlsServer tlsServer) {
    this.tlsServer = tlsServer;
    this.tlsServer.readHandler((request) -> {

      parseRequest(request);

      StringBuilder sb = new StringBuilder();
      sb.append("HTTP/1.0 404 Not Found\r\n");
      sb.append("Content-type: 44\r\n");
      sb.append("Content-length: text/html\r\n");
      sb.append("\r\n\r\n");
      sb.append("<html><body><h1>Not Found</h1></body></html>");
      return ByteBuffer.wrap(sb.toString().getBytes());

    });
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private TlsServer.Builder tlsBuilder;

    private Builder() {
      tlsBuilder = TlsServer.builder();
    }

    public Builder protocols(String... protocol) {
      tlsBuilder.protocols(protocol);
      return this;
    }

    public Builder suites(String... suites) {
      tlsBuilder.suites(suites);
      return this;
    }

    public Builder host(String hostname) {
      tlsBuilder.host(hostname);
      return this;
    }

    public Builder port(int port) {
      tlsBuilder.port(port);
      return this;
    }

    public Builder keyStore(String resourceName) throws IOException {
      tlsBuilder.keyStore(resourceName);
      return this;
    }

    public Builder keyStore(String resourceName, String storePassword) throws IOException {
      tlsBuilder.keyStore(resourceName, storePassword);
      return this;
    }

    public Builder keyStore(String resourceName, String storePassword, String keyPassword)
        throws IOException {
      tlsBuilder.keyStore(resourceName, storePassword, keyPassword);
      return this;
    }

    public Builder keyStore(InputStream keyStore) {
      tlsBuilder.keyStore(keyStore);
      return this;
    }

    public Builder keyStore(InputStream keyStore, String password) {
      tlsBuilder.keyStore(keyStore, password);
      return this;
    }

    public Builder keyStore(InputStream keyStore, String storePassword, String keyPassword) {
      tlsBuilder.keyStore(keyStore, storePassword, keyPassword);
      return this;
    }

    public Builder keyStorePassword(String password) {
      tlsBuilder.keyStorePassword(password);
      return this;
    }

    public Builder keyStoreKeyPassword(String password) {
      tlsBuilder.keyStoreKeyPassword(password);
      return this;
    }

    public Builder trustStore(String resourceName) throws IOException {
      tlsBuilder.trustStore(resourceName);
      return this;
    }

    public Builder trustStore(String resourceName, String password) throws IOException {
      tlsBuilder.trustStore(resourceName, password);
      return this;
    }

    public Builder trustStore(InputStream trustStore) {
      tlsBuilder.trustStore(trustStore);
      return this;
    }

    public Builder trustStore(InputStream trustStore, String password) {
      tlsBuilder.trustStore(trustStore, password);
      return this;
    }

    public HttpsServer build() throws Exception {
      return new HttpsServer(tlsBuilder.build());
    }

  }

  private HttpRequest parseRequest(ByteBuffer buff) {
    HttpRequest.Builder requestBuilder = HttpRequest.newBuilder();

    String request = Charset.defaultCharset().decode(buff).toString();

    String[] requestsLines = request.split("\r\n");
    String[] requestLine = requestsLines[0].split(" ");
    String method = requestLine[0];
    String path = requestLine[1];
    String host = requestsLines[1].split(" ")[1];
    String version = requestLine[2];

    int bodyIndex = 0;
    for (int h = 2; h < requestsLines.length; h++) {
      try {
        String[] header = requestsLines[h].split(":");
        if (h + 2 < requestsLines.length && StringUtils.isEmpty(requestsLines[h])
            && StringUtils.isEmpty(requestsLines[h + 1])) {
          bodyIndex = h + 2;
          break;
        } else if (header.length != 2) {
          continue;
        }
        requestBuilder.header(header[0], header[1]);
      } catch (IllegalArgumentException e) {
        LOG.error(e.getMessage());
      }
    }

    requestBuilder.uri(URI.create("https://" + host + path));
    try {
      requestBuilder.version(Version.valueOf(version.replace('/', '_').replace('.', '_')));
    } catch (IllegalArgumentException e) {
      requestBuilder.version(Version.HTTP_1_1);
    }

    if (bodyIndex > 2) {
      StringBuilder sb = new StringBuilder();
      for (int b = bodyIndex; b < requestsLines.length; b++) {
        sb.append(requestsLines[b]);
        sb.append("\r\n");
      }
      requestBuilder.method(method, BodyPublishers.ofString(sb.toString()));
    } else {
      requestBuilder.method(method, BodyPublishers.noBody());
    }

    return requestBuilder.build();
  }

  public void start() throws Exception {
    this.tlsServer.start();
  }

  public void stop() {
    this.tlsServer.stop();
  }

  public void isActive() {
    this.tlsServer.isActive();
  }

  public int getPort() {
    return this.tlsServer.getPort();
  }

  public String getHostAddress() {
    return this.tlsServer.getHostAddress();
  }

  public String[] getProtocols() {
    return this.tlsServer.getProtocols();
  }

  public String[] getCipherSuites() {
    return this.tlsServer.getCipherSuites();
  }

  public URL getUrl() throws MalformedURLException {
    if (getPort() == 443) {
      return new URL("https://" + getHostAddress());
    }
    return new URL("https://" + getHostAddress() + ":" + getPort());
  }

}
