/*_############################################################################
  _##
  _##  SNMP4J 2 - DefaultTlsTmSecurityCallback.java
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
import org.snmp4j.transport.TLSTM;

import javax.security.auth.x500.X500Principal;
import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * The <code>DefaultTlsTmSecurityCallback</code> resolves the
 * <code>tmSecurityName</code> for incoming requests through
 * a mapping table based on the peer certificates,
 * resolves the local certificate alias through a mapping table
 * based on the target address and accepts peer certificates
 * based on a list of trusted peer and issuer certificates.
 *
 * @author Frank Fock
 * @since 2.0
 */
public class DefaultTlsTmSecurityCallback implements TlsTmSecurityCallback<X509Certificate> {

  private LogAdapter LOGGER = LogFactory.getLogger(DefaultTlsTmSecurityCallback.class);

  private Map<SecurityNameMapping, OctetString> securityNameMapping = new HashMap<SecurityNameMapping, OctetString>();
  private Map<Address, String> localCertMapping = new HashMap<Address, String>();
  private Set<String> acceptedSubjectDN = new HashSet<String>();
  private Set<String> acceptedIssuerDN = new HashSet<String>();

  @Override
  public OctetString getSecurityName(X509Certificate[] peerCertificateChain) {
    for (Map.Entry<SecurityNameMapping,OctetString> entry : securityNameMapping.entrySet()) {
      OctetString fingerprint = entry.getKey().getFingerprint();
      for (X509Certificate cert : peerCertificateChain) {
        OctetString certFingerprint = null;
        certFingerprint = TLSTM.getFingerprint(cert);
        if ((certFingerprint != null) && (certFingerprint.equals(fingerprint))) {
          // possible match found -> now try to map to tmSecurityName
          org.snmp4j.transport.tls.SecurityNameMapping.CertMappingType mappingType = entry.getKey().getType();
          OctetString data = entry.getKey().getData();
          OctetString tmSecurityName = null;
          try {
            tmSecurityName = mapCertToTSN(cert, mappingType, data);
          } catch (CertificateParsingException e) {
            LOGGER.warn("Failed to parse client certificate: " + e.getMessage());
          }
          if ((tmSecurityName != null) && (tmSecurityName.length() <= 32)) {
            return tmSecurityName;
          }
        }
      }
    }
    return null;
  }

  private OctetString mapCertToTSN(X509Certificate cert,
                                   org.snmp4j.transport.tls.SecurityNameMapping.CertMappingType mappingType, OctetString data)
      throws CertificateParsingException
  {
    switch (mappingType) {
      case Specified: {
        return data;
      }
      case SANAny:
      case SANRFC822Name: {
        Object entry = TLSTM.getSubjAltName(cert.getSubjectAlternativeNames(), 1);
        if (entry != null) {
          String[] rfc822Name = ((String)entry).split("@");
          return new OctetString(rfc822Name[0]+"@"+rfc822Name[1].toLowerCase());
        }
        // fall through SANAny
      }
      case SANDNSName: {
        Object entry = TLSTM.getSubjAltName(cert.getSubjectAlternativeNames(), 2);
        if (entry != null) {
          String dNSName = ((String)entry).toLowerCase();
          return new OctetString(dNSName);
        }
      }
      case SANIpAddress: {
        Object entry = TLSTM.getSubjAltName(cert.getSubjectAlternativeNames(), 7);
        if (entry != null) {
          String ipAddress = ((String)entry).toLowerCase();
          if (ipAddress.indexOf(':')>=0) {
            // IPv6 address
            StringBuffer buf = new StringBuffer(16);
            String[] bytes = ipAddress.split(":");
            for (String b : bytes) {
              for (int diff = 2-b.length(); diff>0; diff--) {
                buf.append('0');
              }
              buf.append(b);
            }
            return new OctetString(buf.toString());
          }
          return new OctetString(ipAddress);
        }
      }
      case CommonName: {
        X500Principal x500Principal = cert.getSubjectX500Principal();
        return new OctetString(x500Principal.getName());
      }
    }
    return null;
  }

  @Override
  public boolean isClientCertificateAccepted(X509Certificate peerEndCertificate) {
    return acceptedSubjectDN.contains(peerEndCertificate.getSubjectDN().getName());
  }

  @Override
  public boolean isServerCertificateAccepted(X509Certificate[] peerCertificateChain) {
    String subject = peerCertificateChain[0].getSubjectDN().getName();
    if (acceptedSubjectDN.contains(subject)) {
      return true;
    }
    for (X509Certificate cert : peerCertificateChain) {
      Principal issuerDN = cert.getIssuerDN();
      if ((issuerDN != null) && acceptedIssuerDN.contains(issuerDN.getName())) {
        return true;
      }
    }
    return false;
  }

  @Override
  public boolean isAcceptedIssuer(X509Certificate issuerCertificate) {
    Principal issuerDN = issuerCertificate.getIssuerDN();
    return ((issuerDN != null) && acceptedIssuerDN.contains(issuerDN.getName()));
  }

  @Override
  public String getLocalCertificateAlias(Address targetAddress) {
    String localCert = localCertMapping.get(targetAddress);
    if (localCert == null) {
      return localCertMapping.get(null);
    }
    return localCert;
  }

  public void addSecurityNameMapping(OctetString fingerprint, org.snmp4j.transport.tls.SecurityNameMapping.CertMappingType type, OctetString data, OctetString securityName) {
    securityNameMapping.put(new SecurityNameMapping(fingerprint, data, type, securityName), securityName);
  }

  public OctetString removeSecurityNameMapping(OctetString fingerprint, org.snmp4j.transport.tls.SecurityNameMapping.CertMappingType type, OctetString data) {
    return securityNameMapping.remove(new SecurityNameMapping(fingerprint, data, type, null));
  }

  public void addAcceptedIssuerDN(String issuerDN) {
    acceptedIssuerDN.add(issuerDN);
  }

  public boolean removeAcceptedIssuerDN(String issuerDN) {
    return acceptedIssuerDN.remove(issuerDN);
  }

  public void addAcceptedSubjectDN(String subjectDN) {
    acceptedSubjectDN.add(subjectDN);
  }

  public boolean removeAcceptedSubjectDN(String subjectDN) {
    return acceptedSubjectDN.remove(subjectDN);
  }

  public void addLocalCertMapping(Address address, String certAlias) {
    localCertMapping.put(address, certAlias);
  }
  public String removeLocalCertMapping(Address address) {
    return localCertMapping.remove(address);
  }

}

