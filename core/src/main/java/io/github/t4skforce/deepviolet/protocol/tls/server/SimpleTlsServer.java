package io.github.t4skforce.deepviolet.protocol.tls.server;

import io.github.t4skforce.deepviolet.protocol.tls.TlsRecord;
import io.github.t4skforce.deepviolet.protocol.tls.message.TlsClientHello;
import io.github.t4skforce.deepviolet.protocol.tls.message.TlsServerHello;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsErrorHandler;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsHelloExchange;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.TlsHelloHandler;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.impl.DefaultTlsErrorHandler;
import io.github.t4skforce.deepviolet.protocol.tls.server.handler.impl.DefaultTlsHelloHandler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleTlsServer implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(SimpleTlsServer.class);

  private boolean isActive = true;

  private ExecutorService executor = Executors.newFixedThreadPool(50);

  private ServerSocket serverSocket;

  private List<TlsHelloHandler> helloHandlers = new CopyOnWriteArrayList<>();

  private TlsErrorHandler error = new DefaultTlsErrorHandler();

  private SimpleTlsServer(String hostAddress, int port, List<TlsHelloHandler> hellos,
      TlsErrorHandler errorHandler) throws UnknownHostException, IOException {
    serverSocket = new ServerSocket(port, 0, InetAddress.getByName(hostAddress));
    if (CollectionUtils.isNotEmpty(hellos)) {
      this.helloHandlers.addAll(hellos);
    }
    if (Objects.nonNull(errorHandler)) {
      this.error = errorHandler;
    }
  }

  @Override
  public void run() {
    try {
      while (isActive) {
        try {
          Socket socket = serverSocket.accept();
          executor.submit(new TlsClientHandler(socket, helloHandlers, error));
        } catch (IOException e) {
          this.error.handle(e);
        }
      }
    } finally {
      try {
        serverSocket.close();
      } catch (IOException e) {
        this.error.handle(e);
      }
    }
  }

  public SimpleTlsServer handler(TlsHelloHandler hello) {
    this.helloHandlers.add(hello);
    return this;
  }

  public void stop() {
    isActive = false;
    executor.shutdownNow();
  }

  public int getPort() {
    return serverSocket.getLocalPort();
  }

  public String getHost() {
    return serverSocket.getInetAddress().getHostAddress();
  }

  private class TlsClientHandler extends Thread {
    private final Socket socket;
    private final List<TlsHelloHandler> helloHandlers;
    private final TlsErrorHandler error;

    public TlsClientHandler(Socket socket, List<TlsHelloHandler> helloHandlers,
        TlsErrorHandler exceptionHandler) {
      this.socket = socket;
      this.helloHandlers = helloHandlers;
      this.error = exceptionHandler;
    }

    @Override
    public void run() {
      try (DataInputStream in = new DataInputStream(this.socket.getInputStream());
          DataOutputStream out = new DataOutputStream(this.socket.getOutputStream())) {

        TlsRecord record = TlsRecord.of(in);
        if (record.isHandshake()) {
          byte[] data = record.getData();
          switch (record.getHandhakeType()) {
          case CLIENT_HELLO:
            TlsHelloExchange excahnge = new TlsHelloExchange(this.socket, TlsClientHello.of(data),
                TlsServerHello.builder().build());
            for (TlsHelloHandler handler : this.helloHandlers) {
              handler.handle(excahnge);
            }
            TlsServerHello response = excahnge.getServerHello();
            if (Objects.nonNull(response)) {
              out.write(TlsRecord.of(response).getBytes());
            }
            break;
          default:
            System.err.println(record.getHandhakeType());
            break;
          }
        } else {
          System.out.println(record);
        }
      } catch (AssertionError e) {
        this.error.handle(e);
      } catch (Exception e) {
        this.error.handle(e);
      } finally {
        try {
          if (this.socket.isConnected()) {
            this.socket.close();
          }
        } catch (IOException e) {
          this.error.handle(e);
        }
      }
    }

  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String hostAddress = "localhost";
    private int port = 0;
    private List<TlsHelloHandler> hellos = new ArrayList<>();
    private TlsErrorHandler handler = new DefaultTlsErrorHandler();

    private Builder() {
      super();
      hellos.add(new DefaultTlsHelloHandler());
    }

    public Builder host(String hostAddress) {
      this.hostAddress = hostAddress;
      return this;
    }

    public Builder handler(TlsHelloHandler hello) {
      hellos.add(hello);
      return this;
    }

    public Builder handler(TlsErrorHandler handler) {
      if (Objects.nonNull(handler)) {
        this.handler = handler;
      }
      return this;
    }

    public Builder port(int port) {
      this.port = port;
      return this;
    }

    public SimpleTlsServer build() throws Exception {
      return new SimpleTlsServer(hostAddress, port, hellos, handler);
    }
  }

}
