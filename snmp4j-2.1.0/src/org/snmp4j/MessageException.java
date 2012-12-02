/*_############################################################################
  _## 
  _##  SNMP4J 2 - MessageException.java  
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
package org.snmp4j;

import java.io.IOException;
import org.snmp4j.mp.StatusInformation;

/**
 * The <code>MessageException</code> represents information about an exception
 * occurred during message processing. The associated
 * <code>StatusInformation</code> object provides (if present) detailed
 * information about the error that occurred and the status of the processed
 * message.
 * @author Frank Fock
 * @version 1.0.1
 */
public class MessageException extends IOException {

  private static final long serialVersionUID = 7129156393920783825L;

  private StatusInformation statusInformation;

  public MessageException() {
  }

  /**
   * Creates a <code>MessageException</code> from a
   * <code>StatusInformation</code> object.
   * @param status
   *   a <code>StatusInformation</code> instance.
   */
  public MessageException(StatusInformation status) {
    super(""+status.getErrorIndication());
    setStatusInformation(status);
  }

  public MessageException(String message) {
    super(message);
  }

  public StatusInformation getStatusInformation() {
    return statusInformation;
  }

  public void setStatusInformation(StatusInformation statusInformation) {
    this.statusInformation = statusInformation;
  }
}

