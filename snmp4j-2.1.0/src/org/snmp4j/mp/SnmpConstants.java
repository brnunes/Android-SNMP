/*_############################################################################
  _## 
  _##  SNMP4J 2 - SnmpConstants.java  
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

import org.snmp4j.smi.OID;

/**
 * The <code>SnmpConstants</code> class holds constants, ObjectIDs and
 * Message strings used within SNMP4J.
 *
 * @author Frank Fock
 * @version 1.8
 */
public final class SnmpConstants {

  public static final int DEFAULT_COMMAND_RESPONDER_PORT = 161;
  public static final int DEFAULT_NOTIFICATION_RECEIVER_PORT = 162;

  public static final int MIN_PDU_LENGTH = 484;

  public static final int version1  = 0;
  public static final int version2c = 1;
  public static final int version3  = 3;

  public static final int SNMP_ERROR_SUCCESS                 = 0;
  public static final int SNMP_ERROR_TOO_BIG                 = 1;
  public static final int SNMP_ERROR_NO_SUCH_NAME            = 2;
  public static final int SNMP_ERROR_BAD_VALUE               = 3;
  public static final int SNMP_ERROR_READ_ONLY               = 4;
  public static final int SNMP_ERROR_GENERAL_ERROR           = 5;
  public static final int SNMP_ERROR_NO_ACCESS               = 6;
  public static final int SNMP_ERROR_WRONG_TYPE              = 7;
  public static final int SNMP_ERROR_WRONG_LENGTH            = 8;
  public static final int SNMP_ERROR_WRONG_ENCODING          = 9;
  public static final int SNMP_ERROR_WRONG_VALUE             =10;
  public static final int SNMP_ERROR_NO_CREATION             =11;
  public static final int SNMP_ERROR_INCONSISTENT_VALUE      =12;
  public static final int SNMP_ERROR_RESOURCE_UNAVAILABLE    =13;
  public static final int SNMP_ERROR_COMMIT_FAILED           =14;
  public static final int SNMP_ERROR_UNDO_FAILED             =15;
  public static final int SNMP_ERROR_AUTHORIZATION_ERROR     =16;
  public static final int SNMP_ERROR_NOT_WRITEABLE           =17;
  public static final int SNMP_ERROR_INCONSISTENT_NAME       =18;

  public static final int SNMP_MP_OK                          = 0;
  public static final int SNMP_MP_ERROR                       = -1400;
  public static final int SNMP_MP_UNSUPPORTED_SECURITY_MODEL  = -1402;
  public static final int SNMP_MP_NOT_IN_TIME_WINDOW          = -1403;
  public static final int SNMP_MP_DOUBLED_MESSAGE             = -1404;
  public static final int SNMP_MP_INVALID_MESSAGE             = -1405;
  public static final int SNMP_MP_INVALID_ENGINEID            = -1406;
  public static final int SNMP_MP_NOT_INITIALIZED             = -1407;
  public static final int SNMP_MP_PARSE_ERROR                 = -1408;
  public static final int SNMP_MP_UNKNOWN_MSGID               = -1409;
  public static final int SNMP_MP_MATCH_ERROR                 = -1410;
  public static final int SNMP_MP_COMMUNITY_ERROR             = -1411;
  public static final int SNMP_MP_WRONG_USER_NAME             = -1412;
  public static final int SNMP_MP_BUILD_ERROR                 = -1413;
  public static final int SNMP_MP_USM_ERROR                   = -1414;
  public static final int SNMP_MP_UNKNOWN_PDU_HANDLERS        = -1415;
  public static final int SNMP_MP_UNAVAILABLE_CONTEXT         = -1416;
  public static final int SNMP_MP_UNKNOWN_CONTEXT             = -1417;
  public static final int SNMP_MP_REPORT_SENT                 = -1418;

  public static final int SNMPv1v2c_CSM_OK                       = 0;
  public static final int SNMPv1v2c_CSM_BAD_COMMUNITY_NAME       = 1501;
  public static final int SNMPv1v2c_CSM_BAD_COMMUNITY_USE        = 1502;


  public static final int SNMPv3_USM_OK                          = 0;
  public static final int SNMPv3_USM_ERROR                       = 1401;
  public static final int SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL  = 1403;
  public static final int SNMPv3_USM_UNKNOWN_SECURITY_NAME       = 1404;
  public static final int SNMPv3_USM_ENCRYPTION_ERROR            = 1405;
  public static final int SNMPv3_USM_DECRYPTION_ERROR            = 1406;
  public static final int SNMPv3_USM_AUTHENTICATION_ERROR        = 1407;
  public static final int SNMPv3_USM_AUTHENTICATION_FAILURE      = 1408;
  public static final int SNMPv3_USM_PARSE_ERROR                 = 1409;
  public static final int SNMPv3_USM_UNKNOWN_ENGINEID            = 1410;
  public static final int SNMPv3_USM_NOT_IN_TIME_WINDOW          = 1411;
  public static final int SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL    = 1412;
  public static final int SNMPv3_USM_UNSUPPORTED_PRIVPROTOCOL    = 1413;
  public static final int SNMPv3_USM_ADDRESS_ERROR               = 1414;

  public static final int SNMPv3_TSM_OK                          = 0;
  public static final int SNMPv3_TSM_UNKNOWN_PREFIXES            = 1601;
  public static final int SNMPv3_TSM_INVALID_CACHES              = 1602;
  public static final int SNMPv3_TSM_INADEQUATE_SECURITY_LEVELS  = 1603;

  public static final OID usmStatsUnsupportedSecLevels =
      new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0 });
  public static final OID usmStatsNotInTimeWindows =
      new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0 });
  public static final OID usmStatsUnknownUserNames =
      new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0 });
  public static final OID usmStatsUnknownEngineIDs =
      new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0 });
  public static final OID usmStatsWrongDigests =
      new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0 });
  public static final OID usmStatsDecryptionErrors =
      new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0 });

  public static final OID snmpEngineID =
      new OID(new int[] { 1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0 });

  public static final OID snmpUnknownSecurityModels =
      new OID(new int[] { 1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0 });
  public static final OID snmpInvalidMsgs =
      new OID(new int[] { 1, 3, 6, 1, 6, 3, 11, 2, 1, 2, 0 });
  public static final OID snmpUnknownPDUHandlers =
      new OID(new int[] { 1, 3, 6, 1, 6, 3, 11, 2, 1, 3, 0 });

  // SNMP counters (obsoleted counters are not listed)
  public static final OID snmpInPkts =
    new OID(new int[] { 1,3,6,1,2,1,11,1,0 });
  public static final OID snmpInBadVersions =
    new OID(new int[] { 1,3,6,1,2,1,11,3,0 });
  public static final OID snmpInBadCommunityNames =
    new OID(new int[] { 1,3,6,1,2,1,11,4,0 });
  public static final OID snmpInBadCommunityUses =
    new OID(new int[] { 1,3,6,1,2,1,11,5,0 });
  public static final OID snmpInASNParseErrs =
    new OID(new int[] { 1,3,6,1,2,1,11,6,0 });
  public static final OID snmpSilentDrops =
    new OID(new int[] { 1,3,6,1,2,1,11,31,0 });
  public static final OID snmpProxyDrops =
    new OID(new int[] { 1,3,6,1,2,1,11,32,0 });

  public static final OID snmpTrapOID =
     new OID(new int[] { 1,3,6,1,6,3,1,1,4,1,0 });
   public static final OID snmpTrapEnterprise =
     new OID(new int[] { 1,3,6,1,6,3,1,1,4,3,0 });

  // generic trap prefix
  public static final OID snmpTraps =
      new OID(new int[] { 1,3,6,1,6,3,1,1,5 });
  // standard traps
  public static final OID coldStart =
      new OID(new int[] { 1,3,6,1,6,3,1,1,5,1 });
  public static final OID warmStart =
      new OID(new int[] { 1,3,6,1,6,3,1,1,5,2 });
  public static final OID authenticationFailure =
      new OID(new int[] { 1,3,6,1,6,3,1,1,5,5 });
  public static final OID linkDown =
    new OID(new int[] { 1,3,6,1,6,3,1,1,5,3 });
  public static final OID linkUp =
    new OID(new int[] { 1,3,6,1,6,3,1,1,5,4 });

  // most important system group OIDs
  public static final OID sysDescr =
    new OID(new int[] { 1,3,6,1,2,1,1,1,0 });
  public static final OID sysObjectID =
    new OID(new int[] { 1,3,6,1,2,1,1,2,0 });
  public static final OID sysUpTime =
    new OID(new int[] { 1,3,6,1,2,1,1,3,0 });
  public static final OID sysContact =
    new OID(new int[] { 1,3,6,1,2,1,1,4,0 });
  public static final OID sysName =
    new OID(new int[] { 1,3,6,1,2,1,1,5,0 });
  public static final OID sysLocation =
    new OID(new int[] { 1,3,6,1,2,1,1,6,0 });
  public static final OID sysServices =
    new OID(new int[] { 1,3,6,1,2,1,1,7,0 });
  public static final OID sysOREntry =
    new OID(new int[] { 1,3,6,1,2,1,1,9,1 });

  // contexts
  public static final OID snmpUnavailableContexts =
    new OID(new int[] { 1,3,6,1,6,3,12,1,4,0 });
  public static final OID snmpUnknownContexts =
    new OID(new int[] { 1,3,6,1,6,3,12,1,5,0 });

  // coexistance
  public static final OID snmpTrapAddress =
    new OID(new int[] { 1,3,6,1,6,3,18,1,3,0 });
  public static final OID snmpTrapCommunity =
    new OID(new int[] { 1,3,6,1,6,3,18,1,4,0 });

  public static final OID zeroDotZero = new OID(new int[] { 0,0 });

  // SNMP-TSM-MIB
  public static final OID snmpTsmInvalidCaches =
    new OID(new int[] { 1,3,6,1,2,1,190,1,1,1,0 });
  public static final OID snmpTsmInadequateSecurityLevels =
    new OID(new int[] { 1,3,6,1,2,1,190,1,1,2,0 });
  public static final OID snmpTsmUnknownPrefixes =
    new OID(new int[] { 1,3,6,1,2,1,190,1,1,3,0 });
  public static final OID snmpTsmInvalidPrefixes =
    new OID(new int[] { 1,3,6,1,2,1,190,1,1,4,0 });
  public static final OID snmpTsmConfigurationUsePrefix =
    new OID(new int[] { 1,3,6,1,2,1,190,1,2,1,0 });

  // SNMP-TLS-TM-MIB
    public static final OID snmpTlstmSessionOpens =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,1,0 });
  public static final OID snmpTlstmSessionClientCloses =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,2,0 });
  public static final OID snmpTlstmSessionOpenErrors =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,3,0 });
  public static final OID snmpTlstmSessionAccepts =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,4,0 });
  public static final OID snmpTlstmSessionServerCloses =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,5,0 });
  public static final OID snmpTlstmSessionNoSessions =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,6,0 });
  public static final OID snmpTlstmSessionInvalidClientCertificates =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,7,0 });
  public static final OID snmpTlstmSessionUnknownServerCertificate =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,8,0 });
  public static final OID snmpTlstmSessionInvalidServerCertificates =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,9,0 });
  public static final OID snmpTlstmSessionInvalidCaches =
    new OID(new int[] { 1,3,6,1,2,1,198,2,1,10,0 });

  // SNMP-SSH-TM-MIB
  public static final OID snmpSshtmSessionOpens =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,1,0 });
  public static final OID snmpSshtmSessionCloses =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,2,0 });
  public static final OID snmpSshtmSessionOpenErrors =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,3,0 });
  public static final OID snmpSshtmSessionUserAuthFailures =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,4,0 });
  public static final OID snmpSshtmSessionNoChannels =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,5,0 });
  public static final OID snmpSshtmSessionNoSubsystems =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,6,0 });
  public static final OID snmpSshtmSessionNoSessions =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,7,0 });
  public static final OID snmpSshtmSessionInvalidCaches =
    new OID(new int[] { 1,3,6,1,2,1,189,1,1,8,0 });


  // SNMP framework
  public static final OID snmpSetSerialNo =
      new OID(new int[] { 1,3,6,1,6,3,1,1,6,1,0 });

  public static final String[] SNMP_ERROR_MESSAGES = {
      "Success",
      "PDU encoding too big",
      "No such name",
      "Bad value",
      "Variable is read-only",
      "General variable binding error",
      "No access",
      "Wrong type",
      "Variable binding data with incorrect length",
      "Variable binding data with wrong encoding",
      "Wrong value",
      "Unable to create object",
      "Inconsistent value",
      "Resource unavailable",
      "Commit failed",
      "Undo failed",
      "Authorization error",
      "Not writable",
      "Inconsistent naming used"
  };

  public static String[][] MP_ERROR_MESSAGES = {
      { ""+SNMP_MP_ERROR, "MP error" },
      { ""+SNMP_MP_UNSUPPORTED_SECURITY_MODEL, "Unsupported security model" },
      { ""+SNMP_MP_NOT_IN_TIME_WINDOW, "Message not in time window"},
      { ""+SNMP_MP_DOUBLED_MESSAGE, "Doubled message" },
      { ""+SNMP_MP_INVALID_MESSAGE, "Invalid message" },
      { ""+SNMP_MP_INVALID_ENGINEID, "Invalid engine ID" },
      { ""+SNMP_MP_NOT_INITIALIZED, "MP not initialized" },
      { ""+SNMP_MP_PARSE_ERROR, "MP parse error"},
      { ""+SNMP_MP_UNKNOWN_MSGID, "Unknown message ID"},
      { ""+SNMP_MP_MATCH_ERROR, "MP match error"},
      { ""+SNMP_MP_COMMUNITY_ERROR, "MP community error"},
      { ""+SNMP_MP_WRONG_USER_NAME, "Wrong user name"},
      { ""+SNMP_MP_BUILD_ERROR, "MP build error"},
      { ""+SNMP_MP_USM_ERROR, "USM error"},
      { ""+SNMP_MP_UNKNOWN_PDU_HANDLERS, "Unknown PDU handles"},
      { ""+SNMP_MP_UNAVAILABLE_CONTEXT, "Unavailable context"},
      { ""+SNMP_MP_UNKNOWN_CONTEXT, "Unknown context"},
      { ""+SNMP_MP_REPORT_SENT, "Report sent"}
  };

  public static String[][] USM_ERROR_MESSAGES = {
      { ""+SNMPv3_USM_OK, "USM OK" },
      { ""+SNMPv3_USM_ERROR, "USM error" },
      { ""+SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL, "Unsupported security level" },
      { ""+SNMPv3_USM_UNKNOWN_SECURITY_NAME, "Unknown security name"},
      { ""+SNMPv3_USM_ENCRYPTION_ERROR, "Encryption error"},
      { ""+SNMPv3_USM_DECRYPTION_ERROR, "Decryption error"},
      { ""+SNMPv3_USM_AUTHENTICATION_ERROR, "Authentication error"},
      { ""+SNMPv3_USM_AUTHENTICATION_FAILURE, "Authentication failure"},
      { ""+SNMPv3_USM_PARSE_ERROR, "USM parse error"},
      { ""+SNMPv3_USM_UNKNOWN_ENGINEID, "Unknown engine ID"},
      { ""+SNMPv3_USM_NOT_IN_TIME_WINDOW, "Not in time window"},
      { ""+SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL, "Unsupported authentication protocol"},
      { ""+SNMPv3_USM_UNSUPPORTED_PRIVPROTOCOL, "Unsupported privacy protocol"},
      { ""+SNMPv3_USM_ADDRESS_ERROR, "Address error"}
  };

  public static String mpErrorMessage(int status) {
    String s = ""+status;
    for (int i=0; i<MP_ERROR_MESSAGES.length; i++) {
      if (s.equals(MP_ERROR_MESSAGES[i][0])) {
        return MP_ERROR_MESSAGES[i][1];
      }
    }
    // MPv3 uses USM so scan the USM error messages too:
    s = usmErrorMessage(status);
    return s;
  }

  public static String usmErrorMessage(int status) {
    String s = ""+status;
    for (int i=0; i<USM_ERROR_MESSAGES.length; i++) {
      if (s.equals(USM_ERROR_MESSAGES[i][0])) {
        return USM_ERROR_MESSAGES[i][1];
      }
    }
    return s;
  }

  /**
   * Gets the generic trap ID from a notification OID.
   * @param oid
   *    an OID.
   * @return
   *    -1 if the supplied OID is not a generic trap, otherwise a value >= 0
   *    will be returned that denotes the generic trap ID.
   */
  public static int getGenericTrapID(OID oid) {
    if ((oid == null) || (oid.size() != snmpTraps.size()+1)) {
      return -1;
    }
    if (oid.leftMostCompare(snmpTraps.size(), snmpTraps) == 0) {
      return oid.get(oid.size() - 1) - 1;
    }
    return -1;
  }

  public static OID getTrapOID(OID enterprise, int genericID, int specificID) {
    OID oid;
    if (genericID != 6) {
      oid = new OID(snmpTraps);
      oid.append(genericID+1);
    }
    else {
      oid = new OID(enterprise);
      oid.append(0);
      oid.append(specificID);
    }
    return oid;
  }
}

