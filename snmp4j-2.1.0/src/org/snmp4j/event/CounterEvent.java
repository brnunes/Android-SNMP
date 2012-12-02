/*_############################################################################
  _## 
  _##  SNMP4J 2 - CounterEvent.java  
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
package org.snmp4j.event;

import java.util.EventObject;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.Counter32;
// for JavaDoc
import org.snmp4j.smi.Counter64;

/**
 * <code>CounterEvent</code> is an event object that indicates that a specific
 * counter needs to be incremented.
 * <p>
 * At the same time a <code>CounterEvent</code>
 * can be used by the event originator to retrieve the actual value of the
 * specified counter. Listeners that maintain the specified counter value,
 * must set the new value when receiving the <code>CounterEvent</code> by using
 * the {@link #setCurrentValue(Variable currentValue)} method.
 *
 * @author Frank Fock
 * @version 1.0
 */
public class CounterEvent extends EventObject {

  private static final long serialVersionUID = 7916507798848195425L;

  private OID oid;
  private Variable currentValue = new Counter32();

  /**
   * Creates a <code>CounterEvent</code> for the specified counter.
   * @param source
   *    the source of the event.
   * @param oid
   *    the OID of the counter instance (typically, the counter is a scalar and
   *    thus the OID has to end on zero).
   */
  public CounterEvent(Object source, OID oid) {
    super(source);
    this.oid = oid;
  }

  /**
   * Gets the instance object identifier of the counter.
   * @return
   *    an <code>OID</code>.
   */
  public OID getOid() {
    return oid;
  }

  /**
   * Gets the current value of the counter, as set by the maintainer of the
   * counter (one of the event listeners).
   * @return
   *    a {@link Counter32} or {@link Counter64} instance.
   */
  public Variable getCurrentValue() {
    return currentValue;
  }

  /**
   * Sets the current value of the counter. This method has to be called by
   * the maintainer of the counter's value.
   *
   * @param currentValue
   *    a {@link Counter32} or {@link Counter64} instance.
   */
  public void setCurrentValue(Variable currentValue) {
    this.currentValue = currentValue;
  }
}
