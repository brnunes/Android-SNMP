/*_############################################################################
  _## 
  _##  SNMP4J 2 - StateReference.java  
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
package org.snmp4j.mp;

import java.util.*;

import org.snmp4j.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import java.io.Serializable;


/**
 * The <code>StateReference</code> class represents state information associated
 * with SNMP messages. The state reference is used to send response or report
 * (SNMPv3 only). Depending on the security model not all fields may be filled.
 *
 * @author Frank Fock
 * @version 2.0
 */
public class StateReference implements Serializable {

  private static final long serialVersionUID = 7385215386971310699L;

  private Address address;
  private transient TransportMapping transportMapping;
  private byte[] contextEngineID;
  private byte[] contextName;
  private SecurityModel securityModel;
  private byte[] securityName;
  private int securityLevel;
  private SecurityStateReference securityStateReference;
  private int msgID;
  private int maxSizeResponseScopedPDU;
  private int msgFlags;
  private PduHandle pduHandle;
  private byte[] securityEngineID;
  private int errorCode = 0;
  private List<Integer> retryMsgIDs;

  /**
   * Default constructor.
   */
  public StateReference() {
  }

  /**
   * Creates a state reference for community based security models.
   * @param pduHandle PduHandle
   * @param peerAddress Address
   * @param peerTransport
   *    the <code>TransportMapping</code> to be used to communicate with the
   *    peer.
   * @param secModel SecurityModel
   * @param secName
   *    a community string.
   * @param errorCode
   *    an error code associated with the SNMP message.
   */
  public StateReference(PduHandle pduHandle,
                        Address peerAddress,
                        TransportMapping peerTransport,
                        SecurityModel secModel,
                        byte[] secName,
                        int errorCode) {
    this(0, 0, 65535, pduHandle, peerAddress, peerTransport,
         null, secModel, secName,
         SecurityLevel.NOAUTH_NOPRIV, null, null, null, errorCode);
  }

  /**
   * Creates a state reference for SNMPv3 messages.
   * @param msgID int
   * @param msgFlags int
   * @param maxSizeResponseScopedPDU int
   * @param pduHandle PduHandle
   * @param peerAddress Address
   * @param peerTransport
   *    the <code>TransportMapping</code> to be used to communicate with the
   *    peer.
   * @param secEngineID byte[]
   * @param secModel SecurityModel
   * @param secName byte[]
   * @param secLevel int
   * @param contextEngineID byte[]
   * @param contextName byte[]
   * @param secStateReference SecurityStateReference
   * @param errorCode int
   */
  public StateReference(int msgID,
                        int msgFlags,
                        int maxSizeResponseScopedPDU,
                        PduHandle pduHandle,
                        Address peerAddress,
                        TransportMapping peerTransport,
                        byte[] secEngineID,
                        SecurityModel secModel,
                        byte[] secName,
                        int secLevel,
                        byte[] contextEngineID,
                        byte[] contextName,
                        SecurityStateReference secStateReference,
                        int errorCode) {
    this.msgID = msgID;
    this.msgFlags = msgFlags;
    this.maxSizeResponseScopedPDU = maxSizeResponseScopedPDU;
    this.pduHandle = pduHandle;
    this.address = peerAddress;
    this.transportMapping = peerTransport;
    this.securityEngineID = secEngineID;
    this.securityModel = secModel;
    this.securityName = secName;
    this.securityLevel = secLevel;
    this.contextEngineID = contextEngineID;
    this.contextName = contextName;
    this.securityStateReference = secStateReference;
    this.errorCode = errorCode;
  }

  public boolean isReportable() {
    return ((msgFlags & 0x04) > 0);
  }

  public Address getAddress() {
    return address;
  }
  public void setAddress(org.snmp4j.smi.Address address) {
    this.address = address;
  }
  public void setContextEngineID(byte[] contextEngineID) {
    this.contextEngineID = contextEngineID;
  }
  public byte[] getContextEngineID() {
    return contextEngineID;
  }
  public void setContextName(byte[] contextName) {
    this.contextName = contextName;
  }
  public byte[] getContextName() {
    return contextName;
  }
  public void setSecurityModel(SecurityModel securityModel) {
    this.securityModel = securityModel;
  }
  public SecurityModel getSecurityModel() {
    return securityModel;
  }
  public void setSecurityName(byte[] securityName) {
    this.securityName = securityName;
  }
  public byte[] getSecurityName() {
    return securityName;
  }
  public void setSecurityLevel(int securityLevel) {
    this.securityLevel = securityLevel;
  }
  public int getSecurityLevel() {
    return securityLevel;
  }
  public void setSecurityStateReference(SecurityStateReference securityStateReference) {
    this.securityStateReference = securityStateReference;
  }
  public SecurityStateReference getSecurityStateReference() {
    return securityStateReference;
  }
  public void setMsgID(int msgID) {
    this.msgID = msgID;
  }
  public int getMsgID() {
    return msgID;
  }
  public void setMsgFlags(int msgFlags) {
    this.msgFlags = msgFlags;
  }
  public int getMsgFlags() {
    return msgFlags;
  }
  public void setMaxSizeResponseScopedPDU(int maxSizeResponseScopedPDU) {
    this.maxSizeResponseScopedPDU = maxSizeResponseScopedPDU;
  }
  public int getMaxSizeResponseScopedPDU() {
    return maxSizeResponseScopedPDU;
  }
  public PduHandle getPduHandle() {
    return pduHandle;
  }

  public byte[] getSecurityEngineID() {
    return securityEngineID;
  }

  public int getErrorCode() {
    return errorCode;
  }

  public TransportMapping getTransportMapping() {
    return transportMapping;
  }

  public void setPduHandle(PduHandle pduHandle) {
    this.pduHandle = pduHandle;
  }

  public void setSecurityEngineID(byte[] securityEngineID) {
    this.securityEngineID = securityEngineID;
  }

  public void setErrorCode(int errorCode) {
    this.errorCode = errorCode;
  }

  public void setTransportMapping(TransportMapping transportMapping) {
    this.transportMapping = transportMapping;
  }

  public boolean isMatchingMessageID(int msgID) {
    return ((this.msgID == msgID) ||
            ((retryMsgIDs != null) && (retryMsgIDs.contains(msgID))));
  }

  public boolean equals(Object o) {
    if (o instanceof StateReference) {
      StateReference other = (StateReference) o;
      return ((isMatchingMessageID(other.msgID) ||
               ((other.retryMsgIDs != null) && (other.retryMsgIDs.contains(msgID)))) &&
              equalsExceptMsgID(other));
    }
    return false;
  }

  public boolean equalsExceptMsgID(StateReference other) {
    return (((pduHandle == null) && (other.pduHandle == null)) ||
             (pduHandle != null) && (pduHandle.equals(other.getPduHandle())) &&
            (Arrays.equals(securityEngineID, other.securityEngineID)) &&
            (securityModel.equals(other.securityModel)) &&
            (Arrays.equals(securityName, other.securityName)) &&
            (securityLevel == other.securityLevel) &&
            (Arrays.equals(contextEngineID, other.contextEngineID)) &&
            (Arrays.equals(contextName, other.contextName)));
  }

  public int hashCode() {
    return msgID;
  }

  public String toString() {
    return "StateReference[msgID="+msgID+",pduHandle="+pduHandle+
        ",securityEngineID="+OctetString.fromByteArray(securityEngineID)+
        ",securityModel="+securityModel+
        ",securityName="+OctetString.fromByteArray(securityName)+
        ",securityLevel="+securityLevel+
        ",contextEngineID="+OctetString.fromByteArray(contextEngineID)+
        ",contextName="+OctetString.fromByteArray(contextName)+
        ",retryMsgIDs="+retryMsgIDs+"]";
  }

  public synchronized void addMessageIDs(List<Integer> msgIDs) {
    if (retryMsgIDs == null) {
      retryMsgIDs = new ArrayList<Integer>(msgIDs.size());
    }
    retryMsgIDs.addAll(msgIDs);
  }

  public synchronized List<Integer> getMessageIDs() {
    List<Integer> msgIDs = new ArrayList<Integer>(1 + ((retryMsgIDs != null) ? retryMsgIDs.size() : 0));
    msgIDs.add(msgID);
    if (retryMsgIDs != null) {
      msgIDs.addAll(retryMsgIDs);
    }
    return msgIDs;
  }
}
