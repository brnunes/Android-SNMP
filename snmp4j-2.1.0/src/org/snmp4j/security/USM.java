/*_############################################################################
  _## 
  _##  SNMP4J 2 - USM.java  
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
package org.snmp4j.security;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Vector;

import org.snmp4j.TransportStateReference;
import org.snmp4j.log.*;
import org.snmp4j.asn1.*;
import org.snmp4j.asn1.BER.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.*;
import org.snmp4j.smi.*;

/**
 * The <code>USM</code> class implements the User Based Security Model (USM)
 * as defined in RFC 3414.
 * <p>
 * When a user is added or removed from the USM, a <code>UsmUserEvent</code>
 * is fired and forwarded to registered listeners.
 *
 * @author Frank Fock
 * @version 2.0
 */
public class USM extends SNMPv3SecurityModel {

  private static final int MAXLEN_USMUSERNAME = 32;

  private static final LogAdapter logger = LogFactory.getLogger(USM.class);

  // Table containing localized and non-localized users
  private UsmUserTable userTable;

  private UsmTimeTable timeTable;

  private boolean engineDiscoveryEnabled = true;

  private SecurityProtocols securityProtocols;
  private transient Vector<UsmUserListener> usmUserListeners;
  private CounterSupport counterSupport;

  /**
   * Creates a USM with the support for the supplied security protocols.
   *
   * @param securityProtocols
   *    the security protocols to support.
   * @param localEngineID
   *    the local engine ID.
   * @param engineBoots
   *    the number of engine boots.
   * @since 1.2
   */
  public USM(SecurityProtocols securityProtocols,
             OctetString localEngineID, int engineBoots) {
    this.localEngineID = localEngineID;
    timeTable = new UsmTimeTable(localEngineID, engineBoots);
    userTable = new UsmUserTable();
    this.securityProtocols = securityProtocols;
    counterSupport = CounterSupport.getInstance();
  }

  public int getID() {
    return SECURITY_MODEL_USM;
  }

  @Override
  public boolean supportsEngineIdDiscovery() {
    return true;
  }

  @Override
  public boolean hasAuthoritativeEngineID() {
    return true;
  }

  /**
   * Sets the local engine ID, number of boots, and time after boot.
   * @param localEngineID
   *    the local engine ID.
   * @param engineBoots
   *    the number of engine boots.
   * @param engineTime
   *    the number sendonds since the last boot.
   */
  public void setLocalEngine(OctetString localEngineID,
                             int engineBoots, int engineTime) {
    this.localEngineID = localEngineID;
    timeTable.setLocalTime(new UsmTimeEntry(localEngineID, engineBoots,
                                            engineTime));
  }

  /**
   * Sets the number of engine boots.
   * @param engineBoots
   *    the number of engine boots.
   */
  public void setEngineBoots(int engineBoots) {
    this.timeTable.setEngineBoots(engineBoots);
  }

  /**
   * Returns the number of engine boots counted for the local engine ID.
   * @return
   *    the number of engine boots (zero based).
   */
  public int getEngineBoots() {
    return this.timeTable.getEngineBoots();
  }

  /**
   * Returns the number of seconds since the value of
   * the engineBoots object last changed. When incrementing this object's value
   * would cause it to exceed its maximum, engineBoots is incremented as if a
   * re-initialization had occurred, and this
   * object's value consequently reverts to zero.
   *
   * @return
   *    a positive integer value denoting the number of seconds since
   *    the engineBoots value has been changed.
   * @since 1.2
   */
  public int getEngineTime() {
    return this.timeTable.getEngineTime();
  }

  public SecurityParameters newSecurityParametersInstance() {
    return new UsmSecurityParameters();
  }

  public SecurityStateReference newSecurityStateReference() {
    return new UsmSecurityStateReference();
  }

  public int generateRequestMessage(int snmpVersion,
                                    byte[] globalData,
                                    int maxMessageSize,
                                    int securityModel,
                                    byte[] securityEngineID,
                                    byte[] securityName,
                                    int securityLevel,
                                    BERInputStream scopedPDU,
                                    SecurityParameters securityParameters,
                                    BEROutputStream wholeMsg,
                                    TransportStateReference tmStateReference) throws IOException {

    return generateResponseMessage(snmpVersion,
                                   globalData,
                                   maxMessageSize,
                                   securityModel,
                                   securityEngineID,
                                   securityName,
                                   securityLevel,
                                   scopedPDU,
                                   null,
                                   securityParameters,
                                   wholeMsg);
  }

  /**
   * Checks if the specified user is known by this USM.
   * @param engineID
   *   the engineID of the user (may be <code>null</code> if any target should
   *   match).
   * @param securityName
   *   the security name of the user to earch for.
   * @return
   *   <code>true</code> if the user is either known for the specified engine ID
   *   or without a specific engine ID (discovery only).
   * @since
   */
  public boolean hasUser(OctetString engineID, OctetString securityName) {
    UsmUserEntry entry = userTable.getUser(engineID, securityName);
    if (entry == null) {
      entry = userTable.getUser(securityName);
      if ((entry == null) && (securityName.length() > 0)) {
        return false;
      }
    }
    return true;
  }

  public UsmUserEntry getUser(OctetString engineID, OctetString securityName) {
    if (logger.isDebugEnabled()) {
      logger.debug("getUser(engineID="+engineID.toHexString()+
                   ", securityName="+securityName.toString()+")");
    }
    UsmUserEntry entry = userTable.getUser(engineID, securityName);
    if (entry == null) {
      entry = userTable.getUser(securityName);
      if ((entry == null) && (securityName.length() > 0)) {
        if (logger.isDebugEnabled()) {
          logger.debug("USM.getUser - User '"+securityName+"' unknown");
        }
        return null;
      }
      else {
        if ((entry == null) || (engineID.length() == 0)) {
          // do not add user
          entry = new UsmUserEntry();
          entry.setUserName(securityName);
          entry.setUsmUser(new UsmUser(securityName, null, null, null, null));
          return entry;
        }
        else {
          // add a new user
          OID authProtocolOID = entry.getUsmUser().getAuthenticationProtocol();
          OID privProtocolOID = entry.getUsmUser().getPrivacyProtocol();
          if (authProtocolOID != null) {
            byte[] authKey;
            if (entry.getUsmUser().isLocalized()) {
              authKey =
                  entry.getUsmUser().getAuthenticationPassphrase().getValue();
            }
            else {
              authKey = securityProtocols.passwordToKey(authProtocolOID,
                  entry.getUsmUser().getAuthenticationPassphrase(),
                  engineID.getValue());
            }
            byte[] privKey = null;
            if (privProtocolOID != null) {
              if (entry.getUsmUser().isLocalized()) {
                privKey = entry.getUsmUser().getPrivacyPassphrase().getValue();
              }
              else {
                privKey = securityProtocols.passwordToKey(privProtocolOID,
                    authProtocolOID,
                    entry.getUsmUser().getPrivacyPassphrase(),
                    engineID.getValue());
              }
            }
            entry = addLocalizedUser(engineID.getValue(), securityName,
                                     authProtocolOID, authKey,
                                     privProtocolOID, privKey);
          }
        }
      }
    }
    return entry;
  }

  public int generateResponseMessage(int snmpVersion,
                                     byte[] globalData,
                                     int maxMessageSize,
                                     int securityModel,
                                     byte[] securityEngineID,
                                     byte[] securityName,
                                     int securityLevel,
                                     BERInputStream scopedPDU,
                                     SecurityStateReference securityStateReference,
                                     SecurityParameters securityParameters,
                                     BEROutputStream wholeMsg) throws IOException {

    UsmSecurityParameters usmSecurityParams =
        (UsmSecurityParameters) securityParameters;
    if (securityStateReference != null) {
      // this is a response or report
      UsmSecurityStateReference usmSecurityStateReference =
          (UsmSecurityStateReference) securityStateReference;
      if (usmSecurityStateReference.getSecurityEngineID() == null) {
        usmSecurityParams.setAuthoritativeEngineID(securityEngineID);
        usmSecurityStateReference.setSecurityEngineID(securityEngineID);
      }
      if (usmSecurityStateReference.getSecurityName() == null) {
        OctetString userName = new OctetString(securityName);
        usmSecurityStateReference.setSecurityName(userName.getValue());
        usmSecurityParams.setUserName(userName);

        OctetString secName =
            getSecurityName(new OctetString(securityEngineID), userName);

        if ((secName != null) &&
            (secName.length() <= MAXLEN_USMUSERNAME)) {
          usmSecurityParams.setUserName(secName);
        }

      }
      else {
        usmSecurityParams.setUserName(new OctetString(usmSecurityStateReference.getSecurityName()));
      }
      usmSecurityParams.setAuthenticationProtocol(usmSecurityStateReference.
                                                  getAuthenticationProtocol());
      usmSecurityParams.setPrivacyProtocol(usmSecurityStateReference.
                                           getPrivacyProtocol());
      usmSecurityParams.setAuthenticationKey(usmSecurityStateReference.
                                             getAuthenticationKey());
      usmSecurityParams.setPrivacyKey(usmSecurityStateReference.getPrivacyKey());
    }
    else {
      OctetString secEngineID = new OctetString();
      if (securityEngineID != null) {
        secEngineID.setValue(securityEngineID);
      }
      OctetString secName = new OctetString(securityName);

      UsmUserEntry user;
      if (secEngineID.length() == 0) {
        if (isEngineDiscoveryEnabled()) {
          user = new UsmUserEntry();
        }
        else {
          if (logger.isDebugEnabled()) {
            logger.debug("Engine ID unknown and discovery disabled");
          }
          return SnmpConstants.SNMPv3_USM_UNKNOWN_ENGINEID;
        }
      }
      else {
        user = getUser(secEngineID, secName);
      }
      if (user == null) {
        if (logger.isDebugEnabled()) {
          logger.debug("Security name not found for engineID=" +
                       secEngineID.toHexString() + ", securityName=" +
                       secName.toHexString());
        }
        return SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME;
      }
      AuthenticationProtocol auth =
          securityProtocols.getAuthenticationProtocol(user.getUsmUser().getAuthenticationProtocol());
      PrivacyProtocol priv =
          securityProtocols.getPrivacyProtocol(user.getUsmUser().getPrivacyProtocol());
      usmSecurityParams.setAuthenticationProtocol(auth);
      usmSecurityParams.setPrivacyProtocol(priv);
      usmSecurityParams.setAuthenticationKey(user.getAuthenticationKey());
      usmSecurityParams.setPrivacyKey(user.getPrivacyKey());
      usmSecurityParams.setUserName(user.getUsmUser().getSecurityName());
      usmSecurityParams.setAuthoritativeEngineID(secEngineID.getValue());
    }

    // Check length of userName and engineID
    if (usmSecurityParams.getAuthoritativeEngineID().length > MPv3.MAXLEN_ENGINE_ID) {
      logger.error("Engine ID too long: "+
                   usmSecurityParams.getAuthoritativeEngineID().length+">"+
                   MPv3.MAXLEN_ENGINE_ID+ " for "+
                   new OctetString(usmSecurityParams.getAuthoritativeEngineID())
                   .toHexString());
      return SnmpConstants.SNMPv3_USM_ERROR;
    }
    if (securityName.length > MAXLEN_USMUSERNAME) {
      logger.error("Security name too long: "+
                   usmSecurityParams.getAuthoritativeEngineID().length+">"+
                   MAXLEN_USMUSERNAME+ " for "+
                   new OctetString(securityName).toHexString());
      return SnmpConstants.SNMPv3_USM_ERROR;
    }

    if (securityLevel >= SecurityLevel.AUTH_NOPRIV) {
      if (securityStateReference != null) {
        // request or response
        usmSecurityParams.setAuthoritativeEngineBoots(getEngineBoots());
        usmSecurityParams.setAuthoritativeEngineTime(getEngineTime());
      }
      else {
        // get engineBoots, engineTime
        OctetString secEngineID = new OctetString(securityEngineID);
        UsmTimeEntry entry = timeTable.getTime(secEngineID);
        if (entry == null) {
          entry =
              new UsmTimeEntry(secEngineID,
                               usmSecurityParams.getAuthoritativeEngineBoots(),
                               usmSecurityParams.
                               getAuthoritativeEngineTime());

          timeTable.addEntry(entry);
        }
        else {
          usmSecurityParams.setAuthoritativeEngineBoots(entry.getEngineBoots());
          usmSecurityParams.setAuthoritativeEngineTime(entry.
              getLatestReceivedTime());
        }
      }
    }

    if ((securityLevel >= SecurityLevel.AUTH_NOPRIV) &&
        (usmSecurityParams.getAuthenticationProtocol() == null)) {
      return SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL;
    }

    byte[] scopedPduBytes = buildMessageBuffer(scopedPDU);

    if (securityLevel == SecurityLevel.AUTH_PRIV) {
      if (usmSecurityParams.getPrivacyProtocol() == null) {
        if (logger.isDebugEnabled()) {
          logger.debug("Unsupported security level (missing or unsupported privacy protocol)");
        }
        return SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL;
      }
      logger.debug("RFC3414 §3.1.4.a Outgoing message needs to be encrypted");

      DecryptParams decryptParams = new DecryptParams();
      byte[] encryptedScopedPdu =
          usmSecurityParams.getPrivacyProtocol().
          encrypt(scopedPduBytes, 0, scopedPduBytes.length,
                  usmSecurityParams.getPrivacyKey(),
                  usmSecurityParams.getAuthoritativeEngineBoots(),
                  usmSecurityParams.getAuthoritativeEngineTime(),
                  decryptParams);
      if (encryptedScopedPdu == null) {
        if (logger.isDebugEnabled()) {
          logger.debug("Encryption error");
        }
        return SnmpConstants.SNMPv3_USM_ENCRYPTION_ERROR;
      }
      usmSecurityParams.setPrivacyParameters(new OctetString(decryptParams.
          array));
      OctetString encryptedString = new OctetString(encryptedScopedPdu);
      BEROutputStream os =
          new BEROutputStream(ByteBuffer.allocate(encryptedString.getBERLength()));
      encryptedString.encodeBER(os);
      scopedPduBytes = os.getBuffer().array();
    }
    else {
      logger.debug("RFC3414 §3.1.4.b Outgoing message is not encrypted");
      usmSecurityParams.setPrivacyParameters(new OctetString());
    }

    byte[] wholeMessage;
    if (securityLevel >= SecurityLevel.AUTH_NOPRIV) {
      /* Build message with authentication */
      byte[] blank =
          new byte[AuthenticationProtocol.MESSAGE_AUTHENTICATION_CODE_LENGTH];
      usmSecurityParams.setAuthenticationParameters(new OctetString(blank));
      wholeMessage =
          buildWholeMessage(new Integer32(snmpVersion),
                            scopedPduBytes, globalData, usmSecurityParams);

      int authParamsPos =
          usmSecurityParams.getAuthParametersPosition() +
          usmSecurityParams.getSecurityParametersPosition();

      boolean authOK = usmSecurityParams.getAuthenticationProtocol().
          authenticate(usmSecurityParams.getAuthenticationKey(),
                       wholeMessage,
                       0,
                       wholeMessage.length,
                       new ByteArrayWindow(wholeMessage,
                                           authParamsPos,
                                           AuthenticationProtocol.
                                           MESSAGE_AUTHENTICATION_CODE_LENGTH));

      if (!authOK) {
        if (logger.isDebugEnabled()) {
          logger.debug("Outgoing message could not be authenticated");
        }
        return SnmpConstants.SNMPv3_USM_AUTHENTICATION_ERROR;
      }
    }
    else {
      // Set engineBoots and enigneTime to zero!
      usmSecurityParams.setAuthoritativeEngineBoots(0);
      usmSecurityParams.setAuthenticationParameters(new OctetString());
      usmSecurityParams.setAuthoritativeEngineTime(0);

      //build Message without authentication
      wholeMessage =
          buildWholeMessage(new Integer32(snmpVersion),
                            scopedPduBytes, globalData, usmSecurityParams);
    }
    ByteBuffer buf =
        (ByteBuffer)ByteBuffer.wrap(wholeMessage).position(wholeMessage.length);
    wholeMsg.setBuffer(buf);
    // not necessary: wholeMsg.write(wholeMessage);
    return SnmpConstants.SNMPv3_USM_OK;
  }

  private OctetString getSecurityName(OctetString engineID,
                                      OctetString userName) {
    if (userName.length() == 0) {
      return userName;
    }
    UsmUserEntry user = userTable.getUser(engineID, userName);
    if (user != null) {
      return user.getUsmUser().getSecurityName();
    }
    else if (isEngineDiscoveryEnabled()) {
      user = userTable.getUser(userName);
      if (user != null) {
        return user.getUsmUser().getSecurityName();
      }
    }
    return null;
  }

  public int processIncomingMsg(int snmpVersion, // typically, SNMP version
                                int maxMessageSize, // of the sending SNMP entity - maxHeaderLength of the MP
                                SecurityParameters securityParameters, // for the received message
                                SecurityModel securityModel, // for the received message
                                int securityLevel, // Level of Security
                                BERInputStream wholeMsg, // as received on the wire
                                TransportStateReference tmStateReference,
                                // output parameters
                                OctetString securityEngineID, // authoritative SNMP entity
                                OctetString securityName, // identification of the principal
                                BEROutputStream scopedPDU, // message (plaintext) payload
                                Integer32 maxSizeResponseScopedPDU, // maximum size of the Response PDU
                                SecurityStateReference securityStateReference, // reference to security state information, needed for response
                                StatusInformation statusInfo
                                ) throws IOException {

    UsmSecurityParameters usmSecurityParameters =
        (UsmSecurityParameters) securityParameters;
    UsmSecurityStateReference usmSecurityStateReference =
        (UsmSecurityStateReference) securityStateReference;
    securityEngineID.setValue(usmSecurityParameters.getAuthoritativeEngineID());

    byte[] message = buildMessageBuffer(wholeMsg);

    if ((securityEngineID.length() == 0) ||
        (timeTable.checkEngineID(securityEngineID,
                                 isEngineDiscoveryEnabled()) !=
         SnmpConstants.SNMPv3_USM_OK)) {
      // generate report
      if (logger.isDebugEnabled()) {
        logger.debug("RFC3414 §3.2.3 Unknown engine ID: " +
                     securityEngineID.toHexString());
      }
      securityEngineID.setValue(usmSecurityParameters.
                                getAuthoritativeEngineID());
      securityName.setValue(usmSecurityParameters.getUserName().getValue());

      if (statusInfo != null) {
        CounterEvent event = new CounterEvent(this,
                                              SnmpConstants.
                                              usmStatsUnknownEngineIDs);
        fireIncrementCounter(event);
        statusInfo.setSecurityLevel(new Integer32(securityLevel));
        statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
              event.getCurrentValue()));
        }
        return SnmpConstants.SNMPv3_USM_UNKNOWN_ENGINEID;
      }

    securityName.setValue(usmSecurityParameters.getUserName().getValue());

    int scopedPDUPosition = usmSecurityParameters.getScopedPduPosition();

    // get security name
    if ((usmSecurityParameters.getUserName().length() > 0) ||
        (securityLevel > SecurityLevel.NOAUTH_NOPRIV)) {
      OctetString secName = getSecurityName(securityEngineID,
                                            usmSecurityParameters.getUserName());
      if (secName == null) {
        if (logger.isDebugEnabled()) {
          logger.debug("RFC3414 §3.2.4 Unknown security name: " +
                       securityName.toHexString());
        }
        if (statusInfo != null) {
          CounterEvent event = new CounterEvent(this,
                                                SnmpConstants.usmStatsUnknownUserNames);
          fireIncrementCounter(event);
          statusInfo.setSecurityLevel(new Integer32(SecurityLevel.NOAUTH_NOPRIV));
          statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
              event.getCurrentValue()));
        }
        return SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME;
      }
    }
    else {
      if (logger.isDebugEnabled()) {
        logger.debug("Accepting zero length security name");
      }
      securityName.setValue(new byte[0]);
    }

    if ((usmSecurityParameters.getUserName().length() > 0) ||
        (securityLevel > SecurityLevel.NOAUTH_NOPRIV)) {
      UsmUserEntry user = getUser(securityEngineID, securityName);
      if (user == null) {
        if (logger.isDebugEnabled()) {
          logger.debug("RFC3414 §3.2.4 Unknown security name: " +
                       securityName.toHexString()+ " for engine ID "+
                       securityEngineID.toHexString());
        }
        CounterEvent event =
            new CounterEvent(this, SnmpConstants.usmStatsUnknownUserNames);
        fireIncrementCounter(event);
        if (statusInfo != null) {
          statusInfo.setSecurityLevel(new Integer32(SecurityLevel.NOAUTH_NOPRIV));
          statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
              event.getCurrentValue()));
        }
        return SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME;
      }

      usmSecurityStateReference.setUserName(user.getUserName().getValue());

      AuthenticationProtocol auth =
          securityProtocols.getAuthenticationProtocol(
                                user.getUsmUser().getAuthenticationProtocol());
      PrivacyProtocol priv =
          securityProtocols.getPrivacyProtocol(
                                user.getUsmUser().getPrivacyProtocol());

      if (((securityLevel >= SecurityLevel.AUTH_NOPRIV) && (auth == null)) ||
          (((securityLevel >= SecurityLevel.AUTH_PRIV) && (priv == null)))) {
        if (logger.isDebugEnabled()) {
          logger.debug("RFC3414 §3.2.5 - Unsupported security level: " +
                       securityLevel);
        }
        CounterEvent event =
            new CounterEvent(this, SnmpConstants.usmStatsUnsupportedSecLevels);
        fireIncrementCounter(event);
        statusInfo.setSecurityLevel(new Integer32(SecurityLevel.NOAUTH_NOPRIV));
        statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
            event.getCurrentValue()));
        return SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL;
      }
      if (securityLevel >= SecurityLevel.AUTH_NOPRIV) {
        if (statusInfo != null) {
          int authParamsPos =
              usmSecurityParameters.getAuthParametersPosition() +
              usmSecurityParameters.getSecurityParametersPosition();
          boolean authentic =
              auth.isAuthentic(user.getAuthenticationKey(),
                               message, 0, message.length,
                               new ByteArrayWindow(message, authParamsPos,
              AuthenticationProtocol.MESSAGE_AUTHENTICATION_CODE_LENGTH));
          if (!authentic) {
            if (logger.isDebugEnabled()) {
              logger.debug(
                  "RFC3414 §3.2.6 Wrong digest -> authentication failure: " +
                  usmSecurityParameters.getAuthenticationParameters().toHexString());
            }
            CounterEvent event =
                new CounterEvent(this, SnmpConstants.usmStatsWrongDigests);
            fireIncrementCounter(event);
            statusInfo.setSecurityLevel(new Integer32(SecurityLevel.NOAUTH_NOPRIV));
            statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
                event.getCurrentValue()));
            return SnmpConstants.SNMPv3_USM_AUTHENTICATION_FAILURE;
          }
          usmSecurityStateReference.setAuthenticationKey(user.getAuthenticationKey());
          usmSecurityStateReference.setPrivacyKey(user.getPrivacyKey());
          usmSecurityStateReference.setAuthenticationProtocol(auth);
          usmSecurityStateReference.setPrivacyProtocol(priv);
          // check time
          int status = timeTable.checkTime(new UsmTimeEntry(securityEngineID,
            usmSecurityParameters.getAuthoritativeEngineBoots(),
            usmSecurityParameters.getAuthoritativeEngineTime()));

           switch (status) {
            case SnmpConstants.SNMPv3_USM_NOT_IN_TIME_WINDOW: {
              logger.debug("RFC3414 §3.2.7.a Not in time window; engineID='" +
                           securityEngineID +
                           "', engineBoots=" +
                           usmSecurityParameters.getAuthoritativeEngineBoots() +
                           ", engineTime=" +
                           usmSecurityParameters.getAuthoritativeEngineTime());
              CounterEvent event =
                  new CounterEvent(this, SnmpConstants.usmStatsNotInTimeWindows);
              fireIncrementCounter(event);
              statusInfo.setSecurityLevel(new Integer32(SecurityLevel.AUTH_NOPRIV));
              statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
                  event.getCurrentValue()));
              return status;
            }
            case SnmpConstants.SNMPv3_USM_UNKNOWN_ENGINEID: {
              if (logger.isDebugEnabled()) {
                logger.debug("RFC3414 §3.2.7.b - Unkown engine ID: " +
                             securityEngineID);
              }
              CounterEvent event =
                  new CounterEvent(this, SnmpConstants.usmStatsUnknownEngineIDs);
              fireIncrementCounter(event);
              statusInfo.setSecurityLevel(new Integer32(SecurityLevel.AUTH_NOPRIV));
              statusInfo.setErrorIndication(new VariableBinding(event.getOid(),
                  event.getCurrentValue()));
              return status;

            }
          }
        }
        if (securityLevel >= SecurityLevel.AUTH_PRIV) {
          OctetString privParams = usmSecurityParameters.getPrivacyParameters();
          DecryptParams decryptParams = new DecryptParams(privParams.getValue(),
                                                          0, privParams.length());
          try {
            int scopedPDUHeaderLength = message.length - scopedPDUPosition;
            ByteBuffer bis = ByteBuffer.wrap(message, scopedPDUPosition,
                                             scopedPDUHeaderLength);
            BERInputStream scopedPDUHeader = new BERInputStream(bis);
            long headerStartingPosition = scopedPDUHeader.getPosition();
            int scopedPDULength =
                BER.decodeHeader(scopedPDUHeader, new MutableByte());
            int scopedPDUPayloadPosition =
                scopedPDUPosition +
                  (int)(scopedPDUHeader.getPosition() - headerStartingPosition);
            scopedPDUHeader.close();
            // early release pointer:
            scopedPDUHeader = null;
            byte[] scopedPduBytes =
                priv.decrypt(message, scopedPDUPayloadPosition, scopedPDULength,
                             user.getPrivacyKey(),
                             usmSecurityParameters.getAuthoritativeEngineBoots(),
                             usmSecurityParameters.getAuthoritativeEngineTime(),
                             decryptParams);
            ByteBuffer buf = ByteBuffer.wrap(scopedPduBytes);
            scopedPDU.setFilledBuffer(buf);
          }
          catch (Exception ex) {
            logger.debug("RFC 3414 §3.2.8 Decryption error: "+ex.getMessage());
            return SnmpConstants.SNMPv3_USM_DECRYPTION_ERROR;
          }
        }
        else {
          int scopedPduLength = message.length - scopedPDUPosition;
          ByteBuffer buf =
              ByteBuffer.wrap(message, scopedPDUPosition, scopedPduLength);
          scopedPDU.setFilledBuffer(buf);
        }
      }
      else {
        int scopedPduLength = message.length - scopedPDUPosition;
        ByteBuffer buf =
            ByteBuffer.wrap(message, scopedPDUPosition, scopedPduLength);
        scopedPDU.setFilledBuffer(buf);
      }
    }
    else {
      int scopedPduLength = message.length - scopedPDUPosition;
      ByteBuffer buf =
          ByteBuffer.wrap(message, scopedPDUPosition, scopedPduLength);
      scopedPDU.setFilledBuffer(buf);
    }
    // compute real max size response pdu according  to RFC3414 §3.2.9
    int maxSecParamsOverhead =
        usmSecurityParameters.getBERMaxLength(securityLevel);
    maxSizeResponseScopedPDU.setValue(maxMessageSize -
                                      maxSecParamsOverhead);

    usmSecurityStateReference.setSecurityName(securityName.getValue());
    return SnmpConstants.SNMPv3_USM_OK;
  }

  protected void fireIncrementCounter(CounterEvent e) {
    counterSupport.fireIncrementCounter(e);
  }

  /**
   * Adds an USM user to the internal user name table.
   * @param userName
   *    a user name.
   * @param user
   *    the <code>UsmUser</code> to add.
   */
  public void addUser(OctetString userName, UsmUser user) {
    addUser(userName, new OctetString(), user);
  }

  /**
   * Adds an USM user to the internal user name table.
   * The user's security name is used as userName.
   * @param user
   *    the <code>UsmUser</code> to add.
   * @since 2.0
   */
  public void addUser(UsmUser user) {
    addUser(user.getSecurityName(), new OctetString(), user);
  }

  /**
   * Adds an USM user to the internal user name table and associates it with
   * an authoritative engine ID. This user can only be used with the specified
   * engine ID - other engine IDs cannot be discovered on behalf of this entry.
   * @param userName
   *    a user name.
   * @param engineID
   *    the authoritative engine ID to be associated with this entry. If
   *    <code>engineID</code> is <code>null</code> this method behaves exactly
   *    like {@link #addUser(OctetString userName, UsmUser user)}.
   * @param user
   *    the <code>UsmUser</code> to add.
   */
  public void addUser(OctetString userName, OctetString engineID, UsmUser user) {
    byte[] authKey = null;
    byte[] privKey = null;
    if ((engineID != null) && (engineID.length() > 0)) {
      if (user.getAuthenticationProtocol() != null) {
        if (user.isLocalized()) {
          authKey = user.getAuthenticationPassphrase().getValue();
        }
        else {
          authKey =
              securityProtocols.passwordToKey(user.getAuthenticationProtocol(),
                                              user.getAuthenticationPassphrase(),
                                              engineID.getValue());
        }
        if (user.getPrivacyProtocol() != null) {
          if (user.isLocalized()) {
            privKey = user.getPrivacyPassphrase().getValue();
          }
          else {
            privKey =
                securityProtocols.passwordToKey(user.getPrivacyProtocol(),
                                                user.getAuthenticationProtocol(),
                                                user.getPrivacyPassphrase(),
                                                engineID.getValue());
          }
        }
      }
    }
    OctetString userEngineID;
    if (user.isLocalized()) {
      userEngineID = user.getLocalizationEngineID();
    }
    else {
      userEngineID = (engineID == null) ? new OctetString() : engineID;
    }
    UsmUserEntry entry =
        new UsmUserEntry(userName, userEngineID, user);
    entry.setAuthenticationKey(authKey);
    entry.setPrivacyKey(privKey);
    userTable.addUser(entry);
    fireUsmUserChange(new UsmUserEvent(this, entry, UsmUserEvent.USER_ADDED));
  }

  /**
   * Updates the USM user entry with the same engine ID and user name as the
   * supplied instance and fires an appropriate <code>UsmUserEvent</code>.
   * If the corresponding user entry does not yet exist then it will be added.
   * @param entry
   *    an <code>UsmUserEntry</code> instance not necessarily the same as an
   *    already existing entry.
   * @since 1.2
   */
  public void updateUser(UsmUserEntry entry) {
    UsmUserEntry oldEntry = userTable.addUser(entry);
    fireUsmUserChange(new UsmUserEvent(this, entry,
                                       (oldEntry == null) ?
                                       UsmUserEvent.USER_ADDED:
                                       UsmUserEvent.USER_CHANGED));
  }

  /**
   * Sets the users of this USM. All previously added users and all localized
   * user information will be discarded and replaced by the supplied users.
   *
   * @param users
   *    a possibly empty <code>UsmUser</code> array of users.
   * @since 1.1
   */
  public void setUsers(UsmUser[] users) {
    if ((users == null) || (users.length == 0)) {
      userTable.clear();
    }
    else {
      Vector<UsmUserEntry> v = new Vector<UsmUserEntry>(users.length);
      for (UsmUser user : users) {
        UsmUserEntry entry =
            new UsmUserEntry(user.getSecurityName(),
                (UsmUser) user.clone());
        v.add(entry);
      }
      userTable.setUsers(v);
    }
  }

  /**
   * Returns the <code>UsmUserTable</code> instance used by the USM for local
   * storage of USM user information. The returned table should not be modified,
   * because modifications will not be reported to registered
   * <code>UsmUserListener</code>s.
   *
   * @return
   *    the <code>UsmUserTable</code> instance containing the users known by
   *    this USM.
   */
  public UsmUserTable getUserTable() {
    return userTable;
  }

  /**
   * Returns the <code>UsmTimeTable</code> instance used by this USM for holding
   * timing information about the local and remote SNMP entities.
   *
   * @return UsmTimeTable
   * @since 1.6
   */
  public UsmTimeTable getTimeTable() {
    return timeTable;
  }

  /**
   * Removes an USM user from the internal user name table.
   * @param engineID
   *    the authoritative engine ID associated with the user, or
   *    <code>null</code>
   * @param userName
   *    a user name.
   * @return
   *    the removed <code>UsmUser</code> instance associate with the given
   *    <code>userName</code> or <code>null</code> if such a user could not
   *    be found.
   */
  public UsmUser removeUser(OctetString engineID, OctetString userName) {
    UsmUserEntry entry = userTable.removeUser(engineID, userName);
    if (entry != null) {
      fireUsmUserChange(new UsmUserEvent(this, entry, UsmUserEvent.USER_REMOVED));
      return entry.getUsmUser();
    }
    return null;
  }

  /**
   * Removes all users from the USM.
   */
  public void removeAllUsers() {
    userTable.clear();
    fireUsmUserChange(new UsmUserEvent(this, null, UsmUserEvent.USER_REMOVED));
  }

  /**
   * Adds a localized user to the USM.
   * @param engineID
   *    the engine ID for which the user has been localized.
   * @param userName
   *    the user's name.
   * @param authProtocol
   *    the authentication protocol ID.
   * @param authKey
   *    the authentication key.
   * @param privProtocol
   *    the privacy protocol ID.
   * @param privKey
   *    the privacy key.
   * @return
   *    the added <code>UsmUserEntry</code>.
   */
  public UsmUserEntry addLocalizedUser(byte[] engineID,
                                       OctetString userName,
                                       OID authProtocol, byte[] authKey,
                                       OID privProtocol, byte[] privKey) {
    UsmUserEntry newEntry = new UsmUserEntry(engineID, userName,
                                             authProtocol, authKey,
                                             privProtocol, privKey);
    userTable.addUser(newEntry);
    fireUsmUserChange(new UsmUserEvent(this, newEntry,
                                       UsmUserEvent.USER_ADDED));
    return newEntry;
  }

  /**
   * Checks whether engine ID discovery is enabled or not. If enabled, the USM
   * will try to discover unknown engine IDs "on-the-fly" while processing the
   * message.
   * @return
   *    <code>true</code> if discovery is enabled, <code>false</code> otherwise.
   */
  public boolean isEngineDiscoveryEnabled() {
    return engineDiscoveryEnabled;
  }

  /**
   * Enables or disables automatic engine ID discovery.
   * @param engineDiscoveryEnabled
   *    <code>true</code> if discovery should be enabled,
   *    <code>false</code> otherwise.
   */
  public void setEngineDiscoveryEnabled(boolean engineDiscoveryEnabled) {
    this.engineDiscoveryEnabled = engineDiscoveryEnabled;
  }

  /**
   * Removes a <code>UsmUserListener</code>.
   * @param l
   *    a previously added <code>UsmUserListener</code>.
   */
  public synchronized void removeUsmUserListener(UsmUserListener l) {
    if (usmUserListeners != null && usmUserListeners.contains(l)) {
      usmUserListeners.remove(l);
    }
  }

  /**
   * Adds a <code>UsmUserListener</code> that should be informed whenever the
   * internal USM user table is changed.
   *
   * @param l
   *    a <code>UsmUserListener</code> that should be informed about
   *    {@link UsmUserEvent} events.
   */
  public synchronized void addUsmUserListener(UsmUserListener l) {
    if (usmUserListeners == null) {
      usmUserListeners = new Vector<UsmUserListener>(2);
    }
    if (!usmUserListeners.contains(l)) {
      usmUserListeners.add(l);
    }
  }

  /**
   * Removes the specified engine ID from the internal time cache and thus
   * forces an engine time rediscovery the next time the SNMP engine with
   * the supplied ID is contacted.
   *
   * @param engineID
   *    the SNMP engine ID whose engine time to remove.
   * @since 1.6
   */
  public void removeEngineTime(OctetString engineID) {
    timeTable.removeEntry(engineID);
  }

  /**
   * Fires a <code>UsmUserEvent</code>.
   * @param e
   *    the <code>UsmUserEvent</code> to fire.
   */
  protected void fireUsmUserChange(UsmUserEvent e) {
    if (usmUserListeners != null) {
      Vector<UsmUserListener> listeners = usmUserListeners;
      int count = listeners.size();
      for (int i = 0; i < count; i++) {
        (listeners.elementAt(i)).usmUserChange(e);
      }
    }
  }

  /**
   * Gets the counter support instance that can be used to register for
   * counter incremnetation events.
   * @return
   *    a <code>CounterSupport</code> instance that is used to fire
   *    {@link CounterEvent}.
   */
  public CounterSupport getCounterSupport() {
    return counterSupport;
  }

  /**
   * Returns the security protocol collection used by this USM.
   * @return
   *    a <code>SecurityProtocols</code> instance which is by default the
   *    same instance as returned by {@link SecurityProtocols#getInstance()}.
   * @since 1.2
   */
  public SecurityProtocols getSecurityProtocols() {
    return securityProtocols;
  }

  /**
   * Sets the counter support instance. By default, the singleton instance
   * provided by the {@link CounterSupport} instance is used.
   * @param counterSupport
   *    a <code>CounterSupport</code> subclass instance.
   */
  public void setCounterSupport(CounterSupport counterSupport) {
    if (counterSupport == null) {
      throw new NullPointerException();
    }
    this.counterSupport = counterSupport;
  }
}
