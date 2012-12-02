/*_############################################################################
  _## 
  _##  SNMP4J 2 - ConnectionOrientedTransportMapping.java  
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

import org.snmp4j.*;
import org.snmp4j.smi.Address;
import java.io.IOException;

/**
 * Transport mappings for connection oriented transport protocols have to
 * implement this interface.
 *
 * @author Frank Fock
 * @version 2.0
 * @since 1.7
 */
public interface ConnectionOrientedTransportMapping<A extends Address>
    extends TransportMapping<A> {

  /**
   * Returns the <code>MessageLengthDecoder</code> used by this transport
   * mapping.
   * @return
   *    a MessageLengthDecoder instance.
   */
  MessageLengthDecoder getMessageLengthDecoder();

  /**
   * Sets the <code>MessageLengthDecoder</code> that decodes the total
   * message length from the header of a message.
   *
   * @param messageLengthDecoder
   *    a MessageLengthDecoder instance.
   */
  void setMessageLengthDecoder(MessageLengthDecoder messageLengthDecoder);

  /**
   * Sets the connection timeout. This timeout specifies the time a connection
   * may be idle before it is closed.
   * @param connectionTimeout
   *    the idle timeout in milliseconds. A zero or negative value will disable
   *    any timeout and connections opened by this transport mapping will stay
   *    opened until they are explicitly closed.
   */
  void setConnectionTimeout(long connectionTimeout);

  /**
   * Adds a transport state listener that is to be informed about connection
   * state changes.
   * @param l
   *    a TransportStateListener.
   */
  void addTransportStateListener(TransportStateListener l);

  /**
   * Removes the supplied transport state listener.
   * @param l
   *    a TransportStateListener.
   */
  void removeTransportStateListener(TransportStateListener l);

  /**
   * Closes the connection to the given remote address (socket).
   * @param remoteAddress
   *    the address of the remote socket.
   * @return
   *    <code>true</code> if the connection could be closed and
   *    <code>false</code> if the connection does not exists.
   * @throws IOException
   *    if closing the connection with the specified remote address
   *    fails.
   * @since 1.7.1
   */
  boolean close(A remoteAddress) throws IOException;

}
