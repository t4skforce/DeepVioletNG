package io.github.t4skforce.deepviolet.protocol.tls.server.handler;

import io.github.t4skforce.deepviolet.protocol.tls.message.TlsClientHello;
import io.github.t4skforce.deepviolet.protocol.tls.message.TlsServerHello;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public class TlsHelloExchange {

  private Socket s;
  private TlsClientHello client;
  private TlsServerHello server;

  public TlsHelloExchange(Socket sock, TlsClientHello client, TlsServerHello server) {
    this.s = sock;
    this.client = client;
    this.server = server;
  }

  public TlsClientHello getClientHello() {
    return this.client;
  }

  public TlsServerHello getServerHello() {
    return this.server;
  }

  /**
   * Returns the address of the remote entity invoking this request
   * 
   * @return the InetSocketAddress of the caller
   */
  public InetSocketAddress getRemoteAddress() {
    InetAddress ia = s.getInetAddress();
    int port = s.getPort();
    return new InetSocketAddress(ia, port);
  }

  /**
   * Returns the local address on which the request was received
   * 
   * @return the InetSocketAddress of the local interface
   */
  public InetSocketAddress getLocalAddress() {
    InetAddress ia = s.getLocalAddress();
    int port = s.getLocalPort();
    return new InetSocketAddress(ia, port);
  }

}
