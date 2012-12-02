/*_############################################################################
  _## 
  _##  SNMP4J 2 - PrivDES.java  
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

import org.snmp4j.smi.OID;
import org.snmp4j.log.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import org.snmp4j.smi.OctetString;

/**
 * Privacy protocol class for DES.
 *
 * This class uses DES in CBC mode to encrypt the data. The protocol
 * is defined in the IETF standard "User-based Security Model (USM)
 * for SNMPv3".
 *
 * @author Jochen Katz
 * @version 1.9
 */
public class PrivDES
    implements PrivacyProtocol {

  private static final long serialVersionUID = 2526070176429255416L;

  /**
   * Unique ID of this privacy protocol.
   */
  public static final OID ID = new OID("1.3.6.1.6.3.10.1.2.2");

  private static final int DECRYPT_PARAMS_LENGTH = 8;
  protected Salt salt;

  private static final LogAdapter logger = LogFactory.getLogger(PrivDES.class);

  public PrivDES()
  {
    this.salt = Salt.getInstance();
  }

  public byte[] encrypt(byte[] unencryptedData,
                        int offset,
                        int length,
                        byte[] encryptionKey,
                        long engineBoots,
                        long engineTime,
                        DecryptParams decryptParams) {
    int mySalt = (int)salt.getNext();

    if (encryptionKey.length < 16) {
      logger.error("Wrong Key length: need at least 16 bytes, is " +
                   encryptionKey.length +
                   " bytes.");
      throw new IllegalArgumentException("encryptionKey has illegal length "
                                         + encryptionKey.length
                                         + " (should be at least 16).");
    }

    if ( (decryptParams.array == null) || (decryptParams.length < 8)) {
      decryptParams.array = new byte[8];
    }
    decryptParams.length = 8;
    decryptParams.offset = 0;

    // put salt in decryption_params (sent as priv params)
    if (logger.isDebugEnabled()) {
      logger.debug("Preparing decrypt_params.");
    }
    for (int i = 0; i < 4; ++i) {
      decryptParams.array[3 - i] = (byte) (0xFF & (engineBoots >> (8 * i)));
      decryptParams.array[7 - i] = (byte) (0xFF & (mySalt >> (8 * i)));
    }

    byte[] iv = new byte[8];

    // last eight bytes of key xored with decrypt params are used as iv
    if (logger.isDebugEnabled()) {
      logger.debug("Preparing iv for encryption.");
    }
    for (int i = 0; i < 8; ++i) {
      iv[i] = (byte) (encryptionKey[8 + i] ^ decryptParams.array[i]);
    }

    byte[] encryptedData = null;

    try {
      // now do CBC encryption of the plaintext
      Cipher alg = Cipher.getInstance("DES/CBC/NoPadding");
      SecretKeySpec key =
          new SecretKeySpec(encryptionKey, 0, 8, "DES");
      IvParameterSpec ivSpec = new IvParameterSpec(iv);
      alg.init(Cipher.ENCRYPT_MODE, key, ivSpec);

      // allocate space for encrypted text
      if (length % 8 == 0) {
        encryptedData = alg.doFinal(unencryptedData, offset, length);
      }
      else {
        if (logger.isDebugEnabled()) {
          logger.debug("Using padding.");
        }

        encryptedData = new byte[8 * ( (length / 8) + 1)];
        byte[] tmp = new byte[8];

        int encryptedLength = alg.update(unencryptedData, offset, length,
                                         encryptedData);
        encryptedLength += alg.doFinal(tmp, 0, 8 - (length % 8),
                                       encryptedData, encryptedLength);
      }
    }
    catch (Exception e) {
      logger.error(e);
      if (logger.isDebugEnabled()) {
        e.printStackTrace();
      }
    }

    if (logger.isDebugEnabled()) {
      logger.debug("Encryption finished.");
    }
    return encryptedData;
  }

  /**
   * Decrypts a message using a given decryption key, engine boots count, and
   * engine ID.
   *
   * @param cryptedData
   *    the data to decrypt.
   * @param offset
   *    the offset into <code>cryptedData</code> to start decryption.
   * @param length
   *    the length of the data to decrypt.
   * @param decryptionKey
   *    the decrpytion key.
   * @param engineBoots
   *    the engine boots counter.
   * @param engineTime
   *    the engine time value.
   * @return
   *    the decrypted data, or <code>null</code> if decryption failed.
   */
  public byte[] decrypt(byte[] cryptedData,
                        int offset,
                        int length,
                        byte[] decryptionKey,
                        long engineBoots,
                        long engineTime,
                        DecryptParams decryptParams) {
    if ((length % 8 != 0) ||
        (length < 8) ||
        (decryptParams.length != 8)) {
      throw new IllegalArgumentException(
          "Length (" + length +
          ") is not multiple of 8 or decrypt params has not length 8 ("
          + decryptParams.length + ").");
    }
    if (decryptionKey.length < 16) {
      logger.error("Wrong Key length: need at least 16 bytes, is " +
                   decryptionKey.length +
                   " bytes.");
      throw new IllegalArgumentException("decryptionKey has illegal length "
                                         + decryptionKey.length
                                         + " (should be at least 16).");
    }

    byte[] iv = new byte[8];

    // last eight bytes of key xored with decrypt params are used as iv
    for (int i = 0; i < 8; ++i) {
      iv[i] = (byte) (decryptionKey[8 + i] ^ decryptParams.array[i]);
    }

    byte[] decryptedData = null;
    try {
      // now do CBC decryption of the crypted data
      Cipher alg = Cipher.getInstance("DES/CBC/NoPadding");
      SecretKeySpec key =
          new SecretKeySpec(decryptionKey, 0, 8, "DES");
      IvParameterSpec ivSpec = new IvParameterSpec(iv);
      alg.init(Cipher.DECRYPT_MODE, key, ivSpec);
      decryptedData = alg.doFinal(cryptedData, offset, length);
    }
    catch (Exception e) {
      logger.error(e);
      if (logger.isDebugEnabled()) {
        e.printStackTrace();
      }
    }

    return decryptedData;
  }

  /**
   * Gets the OID uniquely identifying the privacy protocol.
   * @return
   *    an <code>OID</code> instance.
   */
  public OID getID() {
    return (OID) ID.clone();
  }

  public int getEncryptedLength(int scopedPDULength) {
    if (scopedPDULength % 8 == 0) {
      return scopedPDULength;
    }
    return 8 * ( (scopedPDULength / 8) + 1);
  }

  public int getMinKeyLength() {
    return 16;
  }

  public int getDecryptParamsLength() {
    return DECRYPT_PARAMS_LENGTH;
  }

  public int getMaxKeyLength() {
    return getMinKeyLength();
  }

  public byte[] extendShortKey(byte[] shortKey, OctetString password,
                               byte[] engineID,
                               AuthenticationProtocol authProtocol) {
    return shortKey;
  }

}
