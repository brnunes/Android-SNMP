/*_############################################################################
  _##
  _##  SNMP4J 2 - PropertiesTlsTmSecurityCallback.java
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

package org.snmp4j.transport.tls;

import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.util.SnmpConfigurator;

import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * The <code>PropertiesTlsTmSecurityCallback</code> resolves the
 * <code>tmSecurityName</code> for incoming requests by using the
 * (system) properties <code>org.snmp4j.arg.tlsPeerID</code> and
 * <code>org.snmp4j.arg.tlsLocalCA</code>.
 *
 * @author Frank Fock
 * @since 2.0
 */
public class PropertiesTlsTmSecurityCallback
    implements TlsTmSecurityCallback<X509Certificate> {

  private static final LogAdapter LOGGER =
      LogFactory.getLogger(PropertiesTlsTmSecurityCallback.class);

  private boolean serverMode;
  private Properties properties;

  public PropertiesTlsTmSecurityCallback(boolean serverMode) {
    this(System.getProperties(), serverMode);
  }

  public PropertiesTlsTmSecurityCallback(Properties properties, boolean serverMode) {
    this.serverMode = serverMode;
    if (properties == null) {
      throw new NullPointerException();
    }
    this.properties = properties;
  }

  @Override
  public OctetString getSecurityName(X509Certificate[] peerCertificateChain) {
    String securityName = properties.getProperty(SnmpConfigurator.P_SECURITY_NAME, null);
    if (securityName != null) {
      return new OctetString(securityName);
    }
    return null;
  }

  @Override
  public boolean isClientCertificateAccepted(X509Certificate peerEndCertificate) {
    String accepted = properties.getProperty(SnmpConfigurator.P_TLS_LOCAL_ID, "");
    if (serverMode) {
      accepted =  properties.getProperty(SnmpConfigurator.P_TLS_PEER_ID, "");
    }
    return peerEndCertificate.getSubjectDN().getName().equals(accepted);
  }

  @Override
  public boolean isServerCertificateAccepted(X509Certificate[] peerCertificateChain) {
    String acceptedPeer = properties.getProperty(SnmpConfigurator.P_TLS_PEER_ID, "");
    if (serverMode) {
      acceptedPeer =  properties.getProperty(SnmpConfigurator.P_TLS_LOCAL_ID, "");
    }
    String subject = peerCertificateChain[0].getSubjectDN().getName();
    if (subject.equals(acceptedPeer)) {
      return true;
    }
    else {
      LOGGER.warn("Certificate subject '"+subject+
          "' does not match accepted peer '"+acceptedPeer+"'");
    }
    String acceptedCA = properties.getProperty(SnmpConfigurator.P_TLS_TRUST_CA, "");
    for (int i=1; i<peerCertificateChain.length; i++) {
      String ca = peerCertificateChain[i].getIssuerDN().getName();
      if (ca.equals(acceptedCA)) {
        return true;
      }
      else {
        LOGGER.warn("Certification authority '"+ca+
            "' does not match accepted CA '"+acceptedCA+"'");
      }
    }
    return false;
  }

  @Override
  public boolean isAcceptedIssuer(X509Certificate issuerCertificate) {
    String acceptedCA = properties.getProperty(SnmpConfigurator.P_TLS_TRUST_CA, "");
    return issuerCertificate.getIssuerDN().getName().equals(acceptedCA);
  }

  @Override
  public String getLocalCertificateAlias(Address targetAddress) {
    return properties.getProperty(SnmpConfigurator.P_TLS_LOCAL_ID);
  }

}
