/*_############################################################################
  _## 
  _##  SNMP4J 2 - DefaultTcpTransportMapping.java  
  _## 
  _##  Copyright (C) 2003-2011  Frank Fock and Jochen Katz (SNMP4J.org)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/
package org.snmp4j.transport;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;

import org.snmp4j.TransportStateReference;
import org.snmp4j.asn1.*;
import org.snmp4j.asn1.BER.*;
import org.snmp4j.log.*;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.*;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.util.WorkerTask;
import org.snmp4j.util.CommonTimer;

/**
 * The <code>DefaultTcpTransportMapping</code> implements a TCP transport
 * mapping with the Java 1.4 new IO API.
 * <p>
 * It uses a single thread for processing incoming and outgoing messages.
 * The thread is started when the <code>listen</code> method is called, or
 * when an outgoing request is sent using the <code>sendMessage</code> method.
 *
 * @author Frank Fock
 * @version 1.11
 */
public class DefaultTcpTransportMapping extends TcpTransportMapping {

  private static final LogAdapter logger =
      LogFactory.getLogger(DefaultTcpTransportMapping.class);

  private Map<Address, SocketEntry> sockets = new Hashtable<Address, SocketEntry>();
  private WorkerTask server;
  private ServerThread serverThread;

  private CommonTimer socketCleaner;
  // 1 minute default timeout
  private long connectionTimeout = 60000;
  private boolean serverEnabled = false;

  private static final int MIN_SNMP_HEADER_LENGTH = 6;
  private MessageLengthDecoder messageLengthDecoder =
      new SnmpMesssageLengthDecoder();

  /**
   * Creates a default TCP transport mapping with the server for incoming
   * messages disabled.
   * @throws IOException
   *    on failure of binding a local port.
   */
  public DefaultTcpTransportMapping() throws IOException {
    super(new TcpAddress(InetAddress.getLocalHost(), 0));
  }

  /**
   * Creates a default TCP transport mapping that binds to the given address
   * (interface) on the local host.
   *
   * @param serverAddress
   *    the TcpAddress instance that describes the server address to listen
   *    on incoming connection requests.
   * @throws IOException
   *    if the given address cannot be bound.
   */
  public DefaultTcpTransportMapping(TcpAddress serverAddress) throws IOException
  {
    super(serverAddress);
    this.serverEnabled = true;
  }

  /**
   * Listen for incoming and outgoing requests. If the <code>serverEnabled</code>
   * member is <code>false</code> the server for incoming requests is not
   * started. This starts the internal server thread that processes messages.
   * @throws SocketException
   *    when the transport is already listening for incoming/outgoing messages.
   * @throws IOException
   */
  public synchronized void listen() throws java.io.IOException {
    if (server != null) {
      throw new SocketException("Port already listening");
    }
    serverThread = new ServerThread();
    server = SNMP4JSettings.getThreadFactory().createWorkerThread(
      "DefaultTCPTransportMapping_"+getAddress(), serverThread, true);
    if (connectionTimeout > 0) {
      // run as daemon
      socketCleaner = SNMP4JSettings.getTimerFactory().createTimer();
    }
    server.run();
  }

  /**
   * Changes the priority of the server thread for this TCP transport mapping.
   * This method has no effect, if called before {@link #listen()} has been
   * called for this transport mapping or if SNMP4J is configured to use
   * a non-default thread factory.
   *
   * @param newPriority
   *    the new priority.
   * @see Thread#setPriority
   * @since 1.2.2
   */
  public void setPriority(int newPriority) {
    WorkerTask st = server;
    if (st instanceof Thread) {
      ((Thread)st).setPriority(newPriority);
    }
  }

  /**
   * Returns the priority of the internal listen thread.
   * @return
   *    a value between {@link Thread#MIN_PRIORITY} and
   *    {@link Thread#MAX_PRIORITY}.
   * @since 1.2.2
   */
  public int getPriority() {
    WorkerTask st = server;
    if (st instanceof Thread) {
      return ((Thread)st).getPriority();
    }
    else {
      return Thread.NORM_PRIORITY;
    }
  }

  /**
   * Sets the name of the listen thread for this UDP transport mapping.
   * This method has no effect, if called before {@link #listen()} has been
   * called for this transport mapping.
   *
   * @param name
   *    the new thread name.
   * @since 1.6
   */
  public void setThreadName(String name) {
    WorkerTask st = server;
    if (st instanceof Thread) {
      ((Thread)st).setName(name);
    }
  }

  /**
   * Returns the name of the listen thread.
   * @return
   *    the thread name if in listening mode, otherwise <code>null</code>.
   * @since 1.6
   */
  public String getThreadName() {
    WorkerTask st = server;
    if (st != null) {
      return ((Thread)st).getName();
    }
    else {
      return null;
    }
  }

  /**
   * Closes all open sockets and stops the internal server thread that
   * processes messages.
   */
  public void close() {
    WorkerTask st = server;
    if (st != null) {
      st.terminate();
      st.interrupt();
      try {
        st.join();
      }
      catch (InterruptedException ex) {
        logger.warn(ex);
      }
      server = null;
      for (SocketEntry entry : sockets.values()) {
        Socket s = entry.getSocket();
        if (s != null) {
          try {
            SocketChannel sc = s.getChannel();
            s.close();
            if (logger.isDebugEnabled()) {
              logger.debug("Socket to " + entry.getPeerAddress() + " closed");
            }
            if (sc != null) {
              sc.close();
              if (logger.isDebugEnabled()) {
                logger.debug("Socket channel to " +
                    entry.getPeerAddress() + " closed");
              }
            }
          }
          catch (IOException iox) {
            // ingore
            logger.debug(iox);
          }
        }
      }
      if (socketCleaner != null) {
        socketCleaner.cancel();
      }
      socketCleaner = null;
    }
  }

  /**
   * Closes a connection to the supplied remote address, if it is open. This
   * method is particularly useful when not using a timeout for remote
   * connections.
   *
   * @param remoteAddress
   *    the address of the peer socket.
   * @return
   *    <code>true</code> if the connection has been closed and
   *    <code>false</code> if there was nothing to close.
   * @throws IOException
   *    if the remote address cannot be closed due to an IO exception.
   * @since 1.7.1
   */
  public synchronized boolean close(TcpAddress remoteAddress) throws IOException {
    if (logger.isDebugEnabled()) {
      logger.debug("Closing socket for peer address "+remoteAddress);
    }
    SocketEntry entry = sockets.remove(remoteAddress);
    if (entry != null) {
      Socket s = entry.getSocket();
      if (s != null) {
        SocketChannel sc = entry.getSocket().getChannel();
        entry.getSocket().close();
        if (logger.isInfoEnabled()) {
          logger.info("Socket to " + entry.getPeerAddress() + " closed");
        }
        if (sc != null) {
          sc.close();
          if (logger.isDebugEnabled()) {
            logger.debug("Closed socket channel for peer address "+
                         remoteAddress);
          }
        }
      }
      return true;
    }
    return false;
  }

  /**
   * Sends a SNMP message to the supplied address.
   * @param address
   *    an <code>TcpAddress</code>. A <code>ClassCastException</code> is thrown
   *    if <code>address</code> is not a <code>TcpAddress</code> instance.
   * @param message byte[]
   *    the message to sent.
   * @param tmStateReference
   *    the (optional) transport model state reference as defined by
   *    RFC 5590 section 6.1.
   * @throws IOException
   */
  public void sendMessage(TcpAddress address, byte[] message,
                          TransportStateReference tmStateReference)
      throws java.io.IOException
  {
    if (server == null) {
      listen();
    }
    serverThread.sendMessage(address, message, tmStateReference);
  }

  /**
   * Gets the connection timeout. This timeout specifies the time a connection
   * may be idle before it is closed.
   * @return long
   *    the idle timeout in milliseconds.
   */
  public long getConnectionTimeout() {
    return connectionTimeout;
  }

  /**
   * Sets the connection timeout. This timeout specifies the time a connection
   * may be idle before it is closed.
   * @param connectionTimeout
   *    the idle timeout in milliseconds. A zero or negative value will disable
   *    any timeout and connections opened by this transport mapping will stay
   *    opened until they are explicitly closed.
   */
  public void setConnectionTimeout(long connectionTimeout) {
    this.connectionTimeout = connectionTimeout;
  }

  /**
   * Checks whether a server for incoming requests is enabled.
   * @return boolean
   */
  public boolean isServerEnabled() {
    return serverEnabled;
  }

  public MessageLengthDecoder getMessageLengthDecoder() {
    return messageLengthDecoder;
  }

  /**
   * Sets whether a server for incoming requests should be created when
   * the transport is set into listen state. Setting this value has no effect
   * until the {@link #listen()} method is called (if the transport is already
   * listening, {@link #close()} has to be called before).
   * @param serverEnabled
   *    if <code>true</code> if the transport will listens for incoming
   *    requests after {@link #listen()} has been called.
   */
  public void setServerEnabled(boolean serverEnabled) {
    this.serverEnabled = serverEnabled;
  }

  /**
   * Sets the message length decoder. Default message length decoder is the
   * {@link SnmpMesssageLengthDecoder}. The message length decoder must be
   * able to decode the total length of a message for this transport mapping
   * protocol(s).
   * @param messageLengthDecoder
   *    a <code>MessageLengthDecoder</code> instance.
   */
  public void setMessageLengthDecoder(MessageLengthDecoder messageLengthDecoder) {
    if (messageLengthDecoder == null) {
      throw new NullPointerException();
    }
    this.messageLengthDecoder = messageLengthDecoder;
  }

  /**
   * Gets the inbound buffer size for incoming requests. When SNMP packets are
   * received that are longer than this maximum size, the messages will be
   * silently dropped and the connection will be closed.
   * @return
   *    the maximum inbound buffer size in bytes.
   */
  public int getMaxInboundMessageSize() {
    return super.getMaxInboundMessageSize();
  }

  /**
   * Sets the maximum buffer size for incoming requests. When SNMP packets are
   * received that are longer than this maximum size, the messages will be
   * silently dropped and the connection will be closed.
   * @param maxInboundMessageSize
   *    the length of the inbound buffer in bytes.
   */
  public void setMaxInboundMessageSize(int maxInboundMessageSize) {
    this.maxInboundMessageSize = maxInboundMessageSize;
  }


  private synchronized void timeoutSocket(SocketEntry entry) {
    if (connectionTimeout > 0) {
      socketCleaner.schedule(new SocketTimeout(entry), connectionTimeout);
    }
  }

  public boolean isListening() {
    return (server != null);
  }

  /**
   * Sets optional server socket options. The default implementation does
   * nothing.
   * @param serverSocket
   *    the <code>ServerSocket</code> to apply additional non-default options.
   */
  protected void setSocketOptions(ServerSocket serverSocket) {
  }

  class SocketEntry {
    private Socket socket;
    private TcpAddress peerAddress;
    private long lastUse;
    private LinkedList<byte[]> message = new LinkedList<byte[]>();
    private ByteBuffer readBuffer = null;
    private volatile int registrations = 0;

    public SocketEntry(TcpAddress address, Socket socket) {
      this.peerAddress = address;
      this.socket = socket;
      this.lastUse = System.nanoTime();
    }

    public synchronized void addRegistration(Selector selector, int opKey)
        throws ClosedChannelException
    {
      if ((this.registrations & opKey) == 0) {
        this.registrations |= opKey;
        if (logger.isDebugEnabled()) {
          logger.debug("Adding operation "+opKey+" for: " + toString());
        }
        socket.getChannel().register(selector, registrations, this);
      }
      else if (!socket.getChannel().isRegistered()) {
        this.registrations = opKey;
        if (logger.isDebugEnabled()) {
          logger.debug("Registering new operation "+opKey+" for: " + toString());
        }
        socket.getChannel().register(selector, opKey, this);
      }
    }

    public synchronized void removeRegistration(Selector selector, int opKey)
        throws ClosedChannelException {
      if ((this.registrations & opKey) == opKey) {
        this.registrations &= ~opKey;
        socket.getChannel().register(selector, this.registrations, this);
      }
    }

    public synchronized boolean isRegistered(int opKey) {
      return (this.registrations & opKey) == opKey;
    }

    public long getLastUse() {
      return lastUse;
    }

    public void used() {
      lastUse = System.nanoTime();
    }

    public Socket getSocket() {
      return socket;
    }

    public TcpAddress getPeerAddress() {
      return peerAddress;
    }

    public synchronized void addMessage(byte[] message) {
      this.message.add(message);
    }

    public synchronized byte[] nextMessage() {
      if (this.message.size() > 0) {
        return this.message.removeFirst();
      }
      return null;
    }

    public synchronized boolean hasMessage() {
      return !this.message.isEmpty();
    }

    public void setReadBuffer(ByteBuffer byteBuffer) {
      this.readBuffer = byteBuffer;
    }

    public ByteBuffer getReadBuffer() {
      return readBuffer;
    }

    public String toString() {
      return "SocketEntry[peerAddress="+peerAddress+
          ",socket="+socket+",lastUse="+new Date(lastUse)+"]";
    }

    /*
    public boolean equals(Object o) {
      if (o instanceof SocketEntry) {
        SocketEntry other = (SocketEntry)o;
        return other.peerAddress.equals(peerAddress) &&
            ((other.message == message) ||
             ((message != null) && (message.equals(other.message))));
      }
      return false;
    }

    public int hashCode() {
      return peerAddress.hashCode();
    }
*/
  }

  public static class SnmpMesssageLengthDecoder implements MessageLengthDecoder {
    public int getMinHeaderLength() {
      return MIN_SNMP_HEADER_LENGTH;
    }
    public MessageLength getMessageLength(ByteBuffer buf) throws IOException {
      MutableByte type = new MutableByte();
      BERInputStream is = new BERInputStream(buf);
      int ml = BER.decodeHeader(is, type);
      int hl = (int)is.getPosition();
      MessageLength messageLength = new MessageLength(hl, ml);
      return messageLength;
    }
  }

  class SocketTimeout extends TimerTask {
    private SocketEntry entry;

    public SocketTimeout(SocketEntry entry) {
      this.entry = entry;
    }

    public void run() {
      long now = System.nanoTime();
      if ((socketCleaner == null) ||
          ((now - entry.getLastUse())/1000000 >= connectionTimeout)) {
        if (logger.isDebugEnabled()) {
          logger.debug("Socket has not been used for "+
                       (now - entry.getLastUse())+
                       " milliseconds, closing it");
        }
        SocketEntry entryCopy = entry;
        try {
          synchronized (entryCopy) {
            if ((now - entry.getLastUse())/1000000 >= connectionTimeout) {
              sockets.remove(entry.getPeerAddress());
              entryCopy.getSocket().close();
              logger.info("Socket to "+entryCopy.getPeerAddress()+
                  " closed due to timeout");
            }
            else {
              rescheduleCleanup(now);
            }
          }
        }
        catch (IOException ex) {
          logger.error(ex);
        }
      }
      else {
        rescheduleCleanup(now);
      }
    }

    private void rescheduleCleanup(long now) {
      long nextRun = System.currentTimeMillis() +
          (now - entry.getLastUse())/1000000 + connectionTimeout;
      if (logger.isDebugEnabled()) {
        logger.debug("Scheduling " + nextRun);
      }
      socketCleaner.schedule(new SocketTimeout(entry), nextRun);
    }

    public boolean cancel(){
        boolean result = super.cancel();
        // free objects early
        entry = null;
        return result;
    }
  }

  class ServerThread implements WorkerTask {
    private byte[] buf;
    private volatile boolean stop = false;
    private Throwable lastError = null;
    private ServerSocketChannel ssc;
    private Selector selector;

    private LinkedList<SocketEntry> pending = new LinkedList<SocketEntry>();

    public ServerThread() throws IOException {
      buf = new byte[getMaxInboundMessageSize()];
      // Selector for incoming requests
      selector = Selector.open();

      if (serverEnabled) {
        // Create a new server socket and set to non blocking mode
        ssc = ServerSocketChannel.open();
        ssc.configureBlocking(false);

        // Bind the server socket
        InetSocketAddress isa = new InetSocketAddress(tcpAddress.getInetAddress(),
            tcpAddress.getPort());
        setSocketOptions(ssc.socket());
        ssc.socket().bind(isa);
        // Register accepts on the server socket with the selector. This
        // step tells the selector that the socket wants to be put on the
        // ready list when accept operations occur, so allowing multiplexed
        // non-blocking I/O to take place.
        ssc.register(selector, SelectionKey.OP_ACCEPT);
      }
    }

    private void processPending() {
      synchronized (pending) {
        for (int i=0; i<pending.size(); i++) {
          SocketEntry entry = pending.getFirst();
          try {
            // Register the channel with the selector, indicating
            // interest in connection completion and attaching the
            // target object so that we can get the target back
            // after the key is added to the selector's
            // selected-key set
            if (entry.getSocket().isConnected()) {
              entry.addRegistration(selector, SelectionKey.OP_WRITE);
            }
            else {
              entry.addRegistration(selector, SelectionKey.OP_CONNECT);
            }
          }
          catch (CancelledKeyException ckex) {
            logger.warn(ckex);
            pending.remove(entry);
            try {
              entry.getSocket().getChannel().close();
              TransportStateEvent e =
                  new TransportStateEvent(DefaultTcpTransportMapping.this,
                                          entry.getPeerAddress(),
                                          TransportStateEvent.STATE_CLOSED,
                                          null);
              fireConnectionStateChanged(e);
            }
            catch (IOException ex) {
              logger.error(ex);
            }
          }
          catch (IOException iox) {
            logger.error(iox);
            pending.remove(entry);
            // Something went wrong, so close the channel and
            // record the failure
            try {
              entry.getSocket().getChannel().close();
              TransportStateEvent e =
                  new TransportStateEvent(DefaultTcpTransportMapping.this,
                                          entry.getPeerAddress(),
                                          TransportStateEvent.STATE_CLOSED,
                                          iox);
              fireConnectionStateChanged(e);
            }
            catch (IOException ex) {
              logger.error(ex);
            }
            lastError = iox;
            if (SNMP4JSettings.isFowardRuntimeExceptions()) {
              throw new RuntimeException(iox);
            }
          }
        }
      }
    }

    public Throwable getLastError() {
      return lastError;
    }

    public void sendMessage(Address address, byte[] message,
                            TransportStateReference tmStateReference)
        throws java.io.IOException
    {
      Socket s = null;
      SocketEntry entry = sockets.get(address);
      if (logger.isDebugEnabled()) {
        logger.debug("Looking up connection for destination '"+address+
                     "' returned: "+entry);
        logger.debug(sockets.toString());
      }
      if (entry != null) {
        synchronized (entry) {
          entry.used();
          s = entry.getSocket();
        }
      }
      if ((s == null) || (s.isClosed()) || (!s.isConnected())) {
        if (logger.isDebugEnabled()) {
          logger.debug("Socket for address '"+address+
                       "' is closed, opening it...");
        }
        synchronized (pending) {
          pending.remove(entry);
        }
        SocketChannel sc = null;
        try {
          InetSocketAddress targetAddress =
              new InetSocketAddress(((TcpAddress)address).getInetAddress(),
                                    ((TcpAddress)address).getPort());
          if ((s == null) || (s.isClosed())) {
            // Open the channel, set it to non-blocking, initiate connect
            sc = SocketChannel.open();
            sc.configureBlocking(false);
            sc.connect(targetAddress);
          }
          else {
            sc = s.getChannel();
            sc.configureBlocking(false);
            if (!sc.isConnectionPending()) {
              sc.connect(targetAddress);
            }
          }
          s = sc.socket();
          entry = new SocketEntry((TcpAddress)address, s);
          entry.addMessage(message);
          sockets.put(address, entry);

          synchronized (pending) {
            pending.add(entry);
          }

          selector.wakeup();
          logger.debug("Trying to connect to "+address);
        }
        catch (IOException iox) {
          logger.error(iox);
          throw iox;
        }
      }
      else {
        entry.addMessage(message);
        synchronized (pending) {
          pending.add(entry);
        }
        logger.debug("Waking up selector for new message");
        selector.wakeup();
      }
    }


    public void run() {
      // Here's where everything happens. The select method will
      // return when any operations registered above have occurred, the
      // thread has been interrupted, etc.
      try {
        while (!stop) {
          try {
            if (selector.select() > 0) {
              if (stop) {
                break;
              }
              // Someone is ready for I/O, get the ready keys
              Set<SelectionKey> readyKeys = selector.selectedKeys();
              Iterator<SelectionKey> it = readyKeys.iterator();

              // Walk through the ready keys collection and process date requests.
              while (it.hasNext()) {
                try {
                  SelectionKey sk = it.next();
                  it.remove();
                  SocketChannel readChannel = null;
                  TcpAddress incomingAddress = null;
                  if (sk.isAcceptable()) {
                    logger.debug("Key is acceptable");
                    // The key indexes into the selector so you
                    // can retrieve the socket that's ready for I/O
                    ServerSocketChannel nextReady =
                        (ServerSocketChannel) sk.channel();
                    Socket s = nextReady.accept().socket();
                    readChannel = s.getChannel();
                    readChannel.configureBlocking(false);

                    incomingAddress = new TcpAddress(s.getInetAddress(),
                                                     s.getPort());
                    SocketEntry entry = new SocketEntry(incomingAddress, s);
                    entry.addRegistration(selector, SelectionKey.OP_READ);
                    sockets.put(incomingAddress, entry);
                    timeoutSocket(entry);
                    TransportStateEvent e =
                        new TransportStateEvent(DefaultTcpTransportMapping.this,
                                                incomingAddress,
                                                TransportStateEvent.
                                                STATE_CONNECTED,
                                                null);
                    fireConnectionStateChanged(e);
                    if (e.isCancelled()) {
                      logger.warn("Incoming connection cancelled");
                      s.close();
                      sockets.remove(incomingAddress);
                      readChannel = null;
                    }
                  }
                  else if (sk.isWritable()) {
                    logger.debug("Key is writable");
                    incomingAddress = writeData(sk, incomingAddress);
                  }
                  else if (sk.isReadable()) {
                    logger.debug("Key is readable");
                    readChannel = (SocketChannel) sk.channel();
                    incomingAddress =
                        new TcpAddress(readChannel.socket().getInetAddress(),
                                       readChannel.socket().getPort());
                  }
                  else if (sk.isConnectable()) {
                    logger.debug("Key is connectable");
                    connectChannel(sk, incomingAddress);
                  }

                  if (readChannel != null) {
                    logger.debug("Key is reading");
                    try {
                      readMessage(sk, readChannel, incomingAddress);
                    }
                    catch (IOException iox) {
                      // IO exception -> channel closed remotely
                      logger.warn(iox);
                      sk.cancel();
                      readChannel.close();
                      TransportStateEvent e =
                          new TransportStateEvent(DefaultTcpTransportMapping.this,
                                                  incomingAddress,
                                                  TransportStateEvent.
                                                  STATE_DISCONNECTED_REMOTELY,
                                                  iox);
                      fireConnectionStateChanged(e);
                    }
                  }
                }
                catch (CancelledKeyException ckex) {
                  if (logger.isDebugEnabled()) {
                    logger.debug("Selection key cancelled, skipping it");
                  }
                }
              }
            }
          }
          catch (NullPointerException npex) {
            // There seems to happen a NullPointerException within the select()
            npex.printStackTrace();
            logger.warn("NullPointerException within select()?");
            stop = true;
          }
          processPending();
        }
        if (ssc != null) {
          ssc.close();
        }
        if (selector != null) {
          selector.close();
        }
      }
      catch (IOException iox) {
        logger.error(iox);
        lastError = iox;
      }
      if (!stop) {
        stop = true;
        synchronized (DefaultTcpTransportMapping.this) {
          server = null;
        }
      }
      if (logger.isDebugEnabled()) {
        logger.debug("Worker task finished: " + getClass().getName());
      }
    }

    private void connectChannel(SelectionKey sk, TcpAddress incomingAddress) {
      SocketEntry entry = (SocketEntry) sk.attachment();
      try {
        SocketChannel sc = (SocketChannel) sk.channel();
        if (!sc.isConnected()) {
          if (sc.finishConnect()) {
            sc.configureBlocking(false);
            logger.debug("Connected to " + entry.getPeerAddress());
            // make sure conncetion is closed if not used for timeout
            // micro seconds
            timeoutSocket(entry);
            entry.removeRegistration(selector, SelectionKey.OP_CONNECT);
            entry.addRegistration(selector, SelectionKey.OP_WRITE);
          }
          else {
            entry = null;
          }
        }
        if (entry != null) {
          Address addr = (incomingAddress == null) ?
                                      entry.getPeerAddress() : incomingAddress;
          logger.debug("Fire connected event for "+addr);
          TransportStateEvent e =
              new TransportStateEvent(DefaultTcpTransportMapping.this,
                                      addr,
                                      TransportStateEvent.
                                      STATE_CONNECTED,
                                      null);
          fireConnectionStateChanged(e);
        }
      }
      catch (IOException iox) {
        logger.warn(iox);
        sk.cancel();
        closeChannel(sk.channel());
        if (entry != null) {
          pending.remove(entry);
        }
      }
    }

    private TcpAddress writeData(SelectionKey sk, TcpAddress incomingAddress) {
      SocketEntry entry = (SocketEntry) sk.attachment();
      try {
        SocketChannel sc = (SocketChannel) sk.channel();
        incomingAddress =
            new TcpAddress(sc.socket().getInetAddress(),
                           sc.socket().getPort());
        if ((entry != null) && (!entry.hasMessage())) {
          synchronized (pending) {
            pending.remove(entry);
            entry.removeRegistration(selector, SelectionKey.OP_WRITE);
          }
        }
        if (entry != null) {
          writeMessage(entry, sc);
        }
      }
      catch (IOException iox) {
        logger.warn(iox);
        TransportStateEvent e =
            new TransportStateEvent(DefaultTcpTransportMapping.this,
                                    incomingAddress,
                                    TransportStateEvent.
                                    STATE_DISCONNECTED_REMOTELY,
                                    iox);
        fireConnectionStateChanged(e);
        // make sure channel is closed properly:
        closeChannel(sk.channel());
      }
      return incomingAddress;
    }

    private void closeChannel(SelectableChannel channel) {
      try {
        channel.close();
      }
      catch (IOException channelCloseException) {
        logger.warn(channelCloseException);
      }
    }

    private void readMessage(SelectionKey sk, SocketChannel readChannel,
                             TcpAddress incomingAddress) throws IOException {
      SocketEntry entry = (SocketEntry) sk.attachment();
      if (entry == null) {
        // slow but in some cases needed:
        entry = sockets.get(incomingAddress);
      }
      if (entry != null) {
        // note that socket has been used
        entry.used();
        ByteBuffer readBuffer = entry.getReadBuffer();
        if (readBuffer != null) {
          readChannel.read(readBuffer);
          if (readBuffer.hasRemaining()) {
            entry.addRegistration(selector, SelectionKey.OP_READ);
          }
          else {
            entry.setReadBuffer(null); // <== set read buffer of entry to null
            dispatchMessage(incomingAddress, readBuffer, readBuffer.capacity(), entry);
          }
          return;
        }
      }
      ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
      byteBuffer.limit(messageLengthDecoder.getMinHeaderLength());
      if (!readChannel.isOpen()) {
        sk.cancel();
        if (logger.isDebugEnabled()) {
          logger.debug("Read channel not open, no bytes read from " +
                       incomingAddress);
        }
        return;
      }
      long bytesRead = 0;
      try {
        bytesRead = readChannel.read(byteBuffer);
        if (logger.isDebugEnabled()) {
          logger.debug("Reading header " + bytesRead + " bytes from " +
                       incomingAddress);
        }
      }
      catch (ClosedChannelException ccex) {
        sk.cancel();
        if (logger.isDebugEnabled()) {
          logger.debug("Read channel not open, no bytes read from " +
                       incomingAddress);
        }
        return;
      }
      if (bytesRead == messageLengthDecoder.getMinHeaderLength()) {
        MessageLength messageLength =
            messageLengthDecoder.getMessageLength(ByteBuffer.wrap(buf));
        if (logger.isDebugEnabled()) {
          logger.debug("Message length is "+messageLength);
        }
        if ((messageLength.getMessageLength() > getMaxInboundMessageSize()) ||
            (messageLength.getMessageLength() <= 0)) {
          logger.error("Received message length "+messageLength+
                       " is greater than inboundBufferSize "+
                       getMaxInboundMessageSize());
          if (entry != null) {
            Socket s = entry.getSocket();
            if (s != null) {
              s.close();
              logger.info("Socket to " + entry.getPeerAddress() +
                          " closed due to an error");
            }
          }
        }
        else {
          byteBuffer.limit(messageLength.getMessageLength());
          bytesRead += readChannel.read(byteBuffer);
          if (bytesRead == messageLength.getMessageLength()) {
            dispatchMessage(incomingAddress, byteBuffer, bytesRead, entry);
          }
          else {
            byte[] message = new byte[byteBuffer.limit()];
            int buflen = byteBuffer.limit() - byteBuffer.remaining();
            byteBuffer.flip();
            byteBuffer.get(message, 0, buflen);
            ByteBuffer newBuffer = ByteBuffer.wrap(message);
            newBuffer.position(buflen);
            if (entry != null) {
              entry.setReadBuffer(newBuffer);
            }
          }
          if (entry != null) {
            entry.addRegistration(selector, SelectionKey.OP_READ);
          }
        }
      }
      else if (bytesRead < 0) {
        logger.debug("Socket closed remotely");
        sk.cancel();
        readChannel.close();
        TransportStateEvent e =
            new TransportStateEvent(DefaultTcpTransportMapping.this,
                                    incomingAddress,
                                    TransportStateEvent.
                                    STATE_DISCONNECTED_REMOTELY,
                                    null);
        fireConnectionStateChanged(e);
      }
      else if (entry != null) {
        entry.addRegistration(selector, SelectionKey.OP_READ);
      }
    }

    private void dispatchMessage(TcpAddress incomingAddress,
                                 ByteBuffer byteBuffer, long bytesRead,
                                 Object sessionID) {
      byteBuffer.flip();
      if (logger.isDebugEnabled()) {
        logger.debug("Received message from " + incomingAddress +
                     " with length " + bytesRead + ": " +
                     new OctetString(byteBuffer.array(), 0,
                                     (int)bytesRead).toHexString());
      }
      ByteBuffer bis;
      if (isAsyncMsgProcessingSupported()) {
        byte[] bytes = new byte[(int)bytesRead];
        System.arraycopy(byteBuffer.array(), 0, bytes, 0, (int)bytesRead);
        bis = ByteBuffer.wrap(bytes);
      }
      else {
        bis = ByteBuffer.wrap(byteBuffer.array(),
                              0, (int) bytesRead);
      }
      TransportStateReference stateReference =
        new TransportStateReference(DefaultTcpTransportMapping.this, incomingAddress, null,
                                    SecurityLevel.undefined, SecurityLevel.undefined,
                                    false, sessionID);
      fireProcessMessage(incomingAddress, bis, stateReference);
    }

    private void writeMessage(SocketEntry entry, SocketChannel sc) throws
        IOException {
      byte[] message = entry.nextMessage();
      if (message != null) {
        ByteBuffer buffer = ByteBuffer.wrap(message);
        sc.write(buffer);
        if (logger.isDebugEnabled()) {
          logger.debug("Send message with length " +
                       message.length + " to " +
                       entry.getPeerAddress() + ": " +
                       new OctetString(message).toHexString());
        }
        entry.addRegistration(selector, SelectionKey.OP_READ);
      }
      else {
        entry.removeRegistration(selector, SelectionKey.OP_WRITE);
        // Make sure that we did not clear a selection key that was concurrently
        // added:
        if (entry.hasMessage() && !entry.isRegistered(SelectionKey.OP_WRITE)) {
          entry.addRegistration(selector, SelectionKey.OP_WRITE);
          logger.debug("Waking up selector");
          selector.wakeup();
        }
      }
    }

    public void close() {
      stop = true;
      WorkerTask st = server;
      if (st != null) {
        st.terminate();
      }
    }

    public void terminate() {
      stop = true;
      if (logger.isDebugEnabled()) {
        logger.debug("Terminated worker task: " + getClass().getName());
      }
    }

    public void join() {
      if (logger.isDebugEnabled()) {
        logger.debug("Joining worker task: " + getClass().getName());
      }
    }

    public void interrupt() {
      stop = true;
      if (logger.isDebugEnabled()) {
        logger.debug("Interrupting worker task: " + getClass().getName());
      }
      selector.wakeup();
    }
  }

}
