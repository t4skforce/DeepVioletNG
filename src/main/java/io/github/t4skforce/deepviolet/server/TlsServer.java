package io.github.t4skforce.deepviolet.server;

import com.google.common.io.Resources;

import io.github.t4skforce.deepviolet.util.TrustStoreUtils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Largely based on https://github.com/alkarn/sslengine.example
 *
 */
public class TlsServer {

  private static final Logger LOG = LoggerFactory.getLogger(TlsServer.class);

  private boolean active;

  private SSLContext context;

  private Selector selector;

  /**
   * Will contain this peer's application data in plaintext, that will be later encrypted using
   * {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)} and sent to the other peer. This buffer can
   * typically be of any size, as long as it is large enough to contain this peer's outgoing
   * messages. If this peer tries to send a message bigger than buffer's capacity a
   * {@link BufferOverflowException} will be thrown.
   */
  protected ByteBuffer myAppData;

  /**
   * Will contain this peer's encrypted data, that will be generated after
   * {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)} is applied on {@link NioSslPeer#myAppData}. It
   * should be initialized using {@link SSLSession#getPacketBufferSize()}, which returns the size up
   * to which, SSL/TLS packets will be generated from the engine under a session. All SSLEngine
   * network buffers should be sized at least this large to avoid insufficient space problems when
   * performing wrap and unwrap calls.
   */
  protected ByteBuffer myNetData;

  /**
   * Will contain the other peer's (decrypted) application data. It must be large enough to hold the
   * application data from any peer. Can be initialized with
   * {@link SSLSession#getApplicationBufferSize()} for an estimation of the other peer's application
   * data and should be enlarged if this size is not enough.
   */
  protected ByteBuffer peerAppData;

  /**
   * Will contain the other peer's encrypted data. The SSL/TLS protocols specify that
   * implementations should produce packets containing at most 16 KB of plaintext, so a buffer sized
   * to this value should normally cause no capacity problems. However, some implementations violate
   * the specification and generate large records up to 32 KB. If the
   * {@link SSLEngine#unwrap(ByteBuffer, ByteBuffer)} detects large inbound packets, the buffer
   * sizes returned by SSLSession will be updated dynamically, so the this peer should check for
   * overflow conditions and enlarge the buffer using the session's (updated) buffer size.
   */
  protected ByteBuffer peerNetData;

  /**
   * Will be used to execute tasks that may emerge during handshake in parallel with the server's
   * main thread.
   */
  protected ExecutorService executor = Executors.newSingleThreadExecutor();

  private int port;
  private String hostAddress;
  private String[] protocols;
  private String[] suites;

  private Function<ByteBuffer, ByteBuffer> readHandler;

  /**
   * Server is designed to apply an SSL/TLS protocol and listen to an IP address and port.
   *
   * @param protocol - the SSL/TLS protocol that this server will be configured to apply.
   * @param hostAddress - the IP address this server will listen to.
   * @param port - the port this server will listen to.
   * @throws Exception
   */
  public TlsServer(String[] protocols, String[] suites, String hostAddress, int port,
      InputStream keyStore, String keyStorePassword, String keyPassword, InputStream trustStore,
      String trustStorePassword) throws Exception {

    context = SSLContext.getInstance("TLSv1.3");
    context.init(TrustStoreUtils.createKeyManagers(keyStore, keyStorePassword, keyPassword),
        TrustStoreUtils.createTrustManagers(trustStore, trustStorePassword), new SecureRandom());

    SSLEngine engine = context.createSSLEngine();

    this.protocols = protocols;
    if (ArrayUtils.isEmpty(this.protocols)) {
      this.protocols = engine.getSupportedProtocols();
    }
    engine.setEnabledProtocols(this.protocols);

    this.suites = suites;
    if (ArrayUtils.isEmpty(this.suites)) {
      this.suites = engine.getSupportedCipherSuites();
    }
    engine.setEnabledCipherSuites(this.suites);

    SSLSession dummySession = engine.getSession();
    myAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
    myNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
    peerAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
    peerNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
    dummySession.invalidate();

    selector = SelectorProvider.provider().openSelector();
    ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
    serverSocketChannel.configureBlocking(false);
    serverSocketChannel.socket().bind(new InetSocketAddress(hostAddress, port));
    serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

    this.hostAddress = hostAddress;
    this.port = serverSocketChannel.socket().getLocalPort();
    active = true;
  }

  public int getPort() {
    return this.port;
  }

  public String getHostAddress() {
    return this.hostAddress;
  }

  public String[] getProtocols() {
    return this.protocols;
  }

  public String[] getCipherSuites() {
    return this.suites;
  }

  public static Builder builder() {
    return new Builder();
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
      if (port <= 0) {
        throw new IllegalArgumentException("Port number cannot be less than or equal to 0");
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

    public TlsServer build() throws Exception {
      Objects.requireNonNull(keyStore, "Keystore is mandatory");
      return new TlsServer(protocol.toArray(new String[] {}), suites.toArray(new String[] {}),
          hostname, port, keyStore, keyStorePassword, keyPassword, trustStore, trustStorePassword);
    }

  }

  /**
   * Should be called in order the server to start listening to new connections. This method will
   * run in a loop as long as the server is active. In order to stop the server you should use
   * {@link NioSslServer#stop()} which will set it to inactive state and also wake up the listener,
   * which may be in blocking select() state.
   *
   * @throws Exception
   */
  public void start() throws Exception {
    while (isActive()) {
      selector.select();
      Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
      while (selectedKeys.hasNext()) {
        SelectionKey key = selectedKeys.next();
        selectedKeys.remove();
        if (!key.isValid()) {
          continue;
        }
        if (key.isAcceptable()) {
          accept(key);
        } else if (key.isReadable()) {
          read((SocketChannel) key.channel(), (SSLEngine) key.attachment());
        }
      }
    }
  }

  /**
   * Sets the server to an inactive state, in order to exit the reading loop in
   * {@link NioSslServer#start()} and also wakes up the selector, which may be in select() blocking
   * state.
   */
  public void stop() {
    active = false;
    executor.shutdown();
    selector.wakeup();
  }

  public void readHandler(Function<ByteBuffer, ByteBuffer> handler) {
    this.readHandler = handler;
  }

  /**
   * Will be called after a new connection request arrives to the server. Creates the
   * {@link SocketChannel} that will be used as the network layer link, and the {@link SSLEngine}
   * that will encrypt and decrypt all the data that will be exchanged during the session with this
   * specific client.
   *
   * @param key - the key dedicated to the {@link ServerSocketChannel} used by the server to listen
   * to new connection requests.
   * @throws Exception
   */
  public void accept(SelectionKey key) throws Exception {

    SocketChannel socketChannel = ((ServerSocketChannel) key.channel()).accept();
    socketChannel.configureBlocking(false);

    SSLEngine engine = context.createSSLEngine();
    engine.setEnabledProtocols(this.protocols);
    engine.setEnabledCipherSuites(this.suites);
    engine.setUseClientMode(false);
    try {
      engine.beginHandshake();
      if (doHandshake(socketChannel, engine)) {
        socketChannel.register(selector, SelectionKey.OP_READ, engine);
      } else {
        socketChannel.close();
      }
    } catch (IOException e) {
      LOG.error("Handhake error", e);
      closeConnection(socketChannel, engine);
    }
  }

  /**
   * Implements the handshake protocol between two peers, required for the establishment of the
   * SSL/TLS connection. During the handshake, encryption configuration information - such as the
   * list of available cipher suites - will be exchanged and if the handshake is successful will
   * lead to an established SSL/TLS session.
   *
   * <p/>
   * A typical handshake will usually contain the following steps:
   *
   * <ul>
   * <li>1. wrap: ClientHello</li>
   * <li>2. unwrap: ServerHello/Cert/ServerHelloDone</li>
   * <li>3. wrap: ClientKeyExchange</li>
   * <li>4. wrap: ChangeCipherSpec</li>
   * <li>5. wrap: Finished</li>
   * <li>6. unwrap: ChangeCipherSpec</li>
   * <li>7. unwrap: Finished</li>
   * </ul>
   * <p/>
   * Handshake is also used during the end of the session, in order to properly close the connection
   * between the two peers. A proper connection close will typically include the one peer sending a
   * CLOSE message to another, and then wait for the other's CLOSE message to close the transport
   * link. The other peer from his perspective would read a CLOSE message from his peer and then
   * enter the handshake procedure to send his own CLOSE message as well.
   *
   * @param socketChannel - the socket channel that connects the two peers.
   * @param engine - the engine that will be used for encryption/decryption of the data exchanged
   * with the other peer.
   * @return True if the connection handshake was successful or false if an error occurred.
   * @throws IOException - if an error occurs during read/write to the socket channel.
   */
  public boolean doHandshake(SocketChannel socketChannel, SSLEngine engine) throws IOException {

    SSLEngineResult result;
    HandshakeStatus handshakeStatus;
    int appBufferSize = engine.getSession().getApplicationBufferSize();
    ByteBuffer myAppData = ByteBuffer.allocate(appBufferSize);
    ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);
    myNetData.clear();
    peerNetData.clear();

    handshakeStatus = engine.getHandshakeStatus();
    while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED
        && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
      switch (handshakeStatus) {
      case NEED_UNWRAP:
        if (socketChannel.read(peerNetData) < 0) {
          if (engine.isInboundDone() && engine.isOutboundDone()) {
            return false;
          }
          try {
            engine.closeInbound();
          } catch (SSLException e) {
            /// This engine was forced to close inbound, without having received the proper SSL/TLS
            /// close notification message from the peer, due to end of stream.
          }
          engine.closeOutbound();
          // After closeOutbound the engine will be set to WRAP state, in order to try to send a
          // close message to the client.
          handshakeStatus = engine.getHandshakeStatus();
          break;
        }
        peerNetData.flip();
        try {
          result = engine.unwrap(peerNetData, peerAppData);
          peerNetData.compact();
          handshakeStatus = result.getHandshakeStatus();
        } catch (SSLException sslException) {
          // A problem was encountered while processing the data that caused the SSLEngine to abort.
          // Will try to properly close connection...
          engine.closeOutbound();
          handshakeStatus = engine.getHandshakeStatus();
          break;
        }
        switch (result.getStatus()) {
        case OK:
          break;
        case BUFFER_OVERFLOW:
          // Will occur when peerAppData's capacity is smaller than the data derived from
          // peerNetData's unwrap.
          peerAppData = enlargeApplicationBuffer(engine, peerAppData);
          break;
        case BUFFER_UNDERFLOW:
          // Will occur either when no data was read from the peer or when the peerNetData buffer
          // was too small to hold all peer's data.
          peerNetData = handleBufferUnderflow(engine, peerNetData);
          break;
        case CLOSED:
          if (engine.isOutboundDone()) {
            return false;
          } else {
            engine.closeOutbound();
            handshakeStatus = engine.getHandshakeStatus();
            break;
          }
        default:
          throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
        }
        break;
      case NEED_WRAP:
        myNetData.clear();
        try {
          result = engine.wrap(myAppData, myNetData);
          handshakeStatus = result.getHandshakeStatus();
        } catch (SSLException sslException) {
          // A problem was encountered while processing the data that caused the SSLEngine to abort.
          // Will try to properly close connection...
          engine.closeOutbound();
          handshakeStatus = engine.getHandshakeStatus();
          break;
        }
        switch (result.getStatus()) {
        case OK:
          myNetData.flip();
          while (myNetData.hasRemaining()) {
            socketChannel.write(myNetData);
          }
          break;
        case BUFFER_OVERFLOW:
          // Will occur if there is not enough space in myNetData buffer to write all the data that
          // would be generated by the method wrap.
          // Since myNetData is set to session's packet size we should not get to this point because
          // SSLEngine is supposed
          // to produce messages smaller or equal to that, but a general handling would be the
          // following:
          myNetData = enlargePacketBuffer(engine, myNetData);
          break;
        case BUFFER_UNDERFLOW:
          throw new SSLException(
              "Buffer underflow occured after a wrap. I don't think we should ever get here.");
        case CLOSED:
          try {
            myNetData.flip();
            while (myNetData.hasRemaining()) {
              socketChannel.write(myNetData);
            }
            // At this point the handshake status will probably be NEED_UNWRAP so we make sure that
            // peerNetData is clear to read.
            peerNetData.clear();
          } catch (Exception e) {
            // Failed to send server's CLOSE message due to socket channel's failure.
            handshakeStatus = engine.getHandshakeStatus();
          }
          break;
        default:
          throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
        }
        break;
      case NEED_TASK:
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
          executor.execute(task);
        }
        handshakeStatus = engine.getHandshakeStatus();
        break;
      case FINISHED:
        break;
      case NOT_HANDSHAKING:
        break;
      default:
        throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
      }
    }

    return true;

  }

  /**
   * Will be called by the selector when the specific socket channel has data to be read. As soon as
   * the server reads these data, it will call
   * {@link NioSslServer#write(SocketChannel, SSLEngine, String)} to send back a trivial response.
   *
   * @param socketChannel - the transport link used between the two peers.
   * @param engine - the engine used for encryption/decryption of the data exchanged between the two
   * peers.
   * @throws IOException if an I/O error occurs to the socket channel.
   */
  public void read(SocketChannel socketChannel, SSLEngine engine) throws IOException {
    peerNetData.clear();
    try {
      int bytesRead = socketChannel.read(peerNetData);
      if (bytesRead > 0) {
        peerNetData.flip();
        peerAppData.clear();
        while (peerNetData.hasRemaining()) {
          SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
          switch (result.getStatus()) {
          case OK:
            peerAppData.flip();
            break;
          case BUFFER_OVERFLOW:
            peerAppData = enlargeApplicationBuffer(engine, peerAppData);
            break;
          case BUFFER_UNDERFLOW:
            peerNetData = handleBufferUnderflow(engine, peerNetData);
            break;
          case CLOSED:
            // log.debug("Client wants to close connection...");
            closeConnection(socketChannel, engine);
            // log.debug("Goodbye client!");
            return;
          default:
            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
          }
        }

        if (readHandler != null) {
          ByteBuffer response = readHandler.apply(ByteBuffer.wrap(peerAppData.array()));
          if (response != null && response.hasRemaining()) {
            write(socketChannel, engine, response);
          } else {
            write(socketChannel, engine, "error");
          }
        } else {
          write(socketChannel, engine, "error");
        }
        closeConnection(socketChannel, engine);

      } else if (bytesRead < 0) {
        LOG.error("Received end of stream. Will try to close connection with client...");
        handleEndOfStream(socketChannel, engine);
      }
    } catch (SocketException e) {
      LOG.error("SocketException: " + e.getMessage());
      handleEndOfStream(socketChannel, engine);
    }
  }

  /**
   * Will send a message back to a client.
   *
   * @param key - the key dedicated to the socket channel that will be used to write to the client.
   * @param message - the message to be sent.
   * @throws IOException if an I/O error occurs to the socket channel.
   */
  public void write(SocketChannel socketChannel, SSLEngine engine, String message)
      throws IOException {
    write(socketChannel, engine, ByteBuffer.wrap(message.getBytes()));
  }

  public void write(SocketChannel socketChannel, SSLEngine engine, ByteBuffer message)
      throws IOException {
    myAppData.clear();
    myAppData.put(message);
    myAppData.flip();
    while (myAppData.hasRemaining()) {
      // The loop has a meaning for (outgoing) messages larger than 16KB.
      // Every wrap call will remove 16KB from the original message and send it to the remote peer.
      myNetData.clear();
      SSLEngineResult result = engine.wrap(myAppData, myNetData);
      switch (result.getStatus()) {
      case OK:
        myNetData.flip();
        while (myNetData.hasRemaining()) {
          socketChannel.write(myNetData);
        }
        break;
      case BUFFER_OVERFLOW:
        myNetData = enlargePacketBuffer(engine, myNetData);
        break;
      case BUFFER_UNDERFLOW:
        throw new SSLException(
            "Buffer underflow occured after a wrap. I don't think we should ever get here.");
      case CLOSED:
        closeConnection(socketChannel, engine);
        return;
      default:
        throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
      }
    }
  }

  private ByteBuffer enlargePacketBuffer(SSLEngine engine, ByteBuffer buffer) {
    return enlargeBuffer(buffer, engine.getSession().getPacketBufferSize());
  }

  private ByteBuffer enlargeApplicationBuffer(SSLEngine engine, ByteBuffer buffer) {
    return enlargeBuffer(buffer, engine.getSession().getApplicationBufferSize());
  }

  /**
   * Compares <code>sessionProposedCapacity<code> with buffer's capacity. If buffer's capacity is
   * smaller, returns a buffer with the proposed capacity. If it's equal or larger, returns a buffer
   * with capacity twice the size of the initial one.
   *
   * @param buffer - the buffer to be enlarged.
   * @param sessionProposedCapacity - the minimum size of the new buffer, proposed by
   * {@link SSLSession}.
   * @return A new buffer with a larger capacity.
   */
  private ByteBuffer enlargeBuffer(ByteBuffer buffer, int sessionProposedCapacity) {
    if (sessionProposedCapacity > buffer.capacity()) {
      return ByteBuffer.allocate(sessionProposedCapacity).put(buffer);
    }
    return ByteBuffer.allocate(buffer.capacity() * 2).put(buffer);
  }

  /**
   * Handles {@link SSLEngineResult.Status#BUFFER_UNDERFLOW}. Will check if the buffer is already
   * filled, and if there is no space problem will return the same buffer, so the client tries to
   * read again. If the buffer is already filled will try to enlarge the buffer either to session's
   * proposed size or to a larger capacity. A buffer underflow can happen only after an unwrap, so
   * the buffer will always be a peerNetData buffer.
   *
   * @param buffer - will always be peerNetData buffer.
   * @param engine - the engine used for encryption/decryption of the data exchanged between the two
   * peers.
   * @return The same buffer if there is no space problem or a new buffer with the same data but
   * more space.
   * @throws Exception
   */
  private ByteBuffer handleBufferUnderflow(SSLEngine engine, ByteBuffer buffer) {
    if (engine.getSession().getPacketBufferSize() < buffer.limit()) {
      return buffer;
    } else {
      ByteBuffer replaceBuffer = enlargePacketBuffer(engine, buffer);
      buffer.flip();
      replaceBuffer.put(buffer);
      return replaceBuffer;
    }
  }

  /**
   * This method should be called when this peer wants to explicitly close the connection or when a
   * close message has arrived from the other peer, in order to provide an orderly shutdown.
   * <p/>
   * It first calls {@link SSLEngine#closeOutbound()} which prepares this peer to send its own close
   * message and sets {@link SSLEngine} to the <code>NEED_WRAP</code> state. Then, it delegates the
   * exchange of close messages to the handshake method and finally, it closes socket channel.
   *
   * @param socketChannel - the transport link used between the two peers.
   * @param engine - the engine used for encryption/decryption of the data exchanged between the two
   * peers.
   * @throws IOException if an I/O error occurs to the socket channel.
   */
  public void closeConnection(SocketChannel socketChannel, SSLEngine engine) throws IOException {
    engine.closeOutbound();
    doHandshake(socketChannel, engine);
    socketChannel.close();
  }

  /**
   * In addition to orderly shutdowns, an unorderly shutdown may occur, when the transport link
   * (socket channel) is severed before close messages are exchanged. This may happen by getting an
   * -1 or {@link IOException} when trying to read from the socket channel, or an
   * {@link IOException} when trying to write to it. In both cases {@link SSLEngine#closeInbound()}
   * should be called and then try to follow the standard procedure.
   *
   * @param socketChannel - the transport link used between the two peers.
   * @param engine - the engine used for encryption/decryption of the data exchanged between the two
   * peers.
   * @throws IOException if an I/O error occurs to the socket channel.
   */
  public void handleEndOfStream(SocketChannel socketChannel, SSLEngine engine) throws IOException {
    try {
      engine.closeInbound();
    } catch (Exception e) {
      LOG.error("Forced to close inbound, due to end of stream.");
    }
    closeConnection(socketChannel, engine);
  }

  /**
   * Determines if the the server is active or not.
   *
   * @return if the server is active or not.
   */
  public boolean isActive() {
    return active;
  }
}
