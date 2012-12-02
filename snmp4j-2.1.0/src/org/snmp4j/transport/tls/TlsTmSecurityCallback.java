/*_############################################################################
  _##
  _##  SNMP4J 2 - TlsTmSecurityNameCallback.java
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

import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;

import java.security.cert.Certificate;

/**
 * The <code>TlsTmSecurityCallback</code> is implemented by the
 * SnmpTlsMib (of SNMP4J-Agent), for example, to resolve (lookup) the
 * <code>tmSecurityName</code> for incoming requests.
 *
 * @author Frank Fock
 * @version 2.0
 * @since 2.0
 */
public interface TlsTmSecurityCallback<C extends Certificate> {

  /**
   * Gets the tmSecurityName (see RFC 5953) from the certificate chain
   * of the communication peer that needs to be authenticated.
   *
   * @param peerCertificateChain
   *    an array of {@link Certificate}s with the peer's own certificate
   *    first followed by any CA authorities.
   * @return
   *    the tmSecurityName as defined by RFC 5953.
   */
  OctetString getSecurityName(C[] peerCertificateChain);

  /**
   * Check if the supplied peer end certificate is accepted as client.
   * @param peerEndCertificate
   *    a client Certificate instance to check acceptance for.
   * @return
   *    <tt>true</tt> if the certificate is accepted.
   */
  boolean isClientCertificateAccepted(C peerEndCertificate);

  /**
   * Check if the supplied peer certificate chain is accepted as server.
   * @param peerCertificateChain
   *    a server Certificate chain to check acceptance for.
   * @return
   *    <tt>true</tt> if the certificate chain is accepted.
   */
  boolean isServerCertificateAccepted(C[] peerCertificateChain);

  /**
   * Check if the supplied issuer certificate is accepted as server.
   * @param issuerCertificate
   *    an issuer Certificate instance to check acceptance for.
   * @return
   *    <tt>true</tt> if the certificate is accepted.
   */
  boolean isAcceptedIssuer(C issuerCertificate);

  /**
   * Gets the local certificate alias to be used for the supplied
   * target address.
   * @param targetAddress
   *    a target address or <tt>null</tt> if the default local
   *    certificate alias needs to be retrieved.
   * @return
   *    the requested local certificate alias, if known.
   *    Otherwise <tt>null</tt> is returned which could cause
   *    a protocol violation if the local key store contains more
   *    than one certificate.
   */
  String getLocalCertificateAlias(Address targetAddress);

}
