/*_############################################################################
  _## 
  _##  SNMP4J 2 - ConsoleLogFactory.java  
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
package org.snmp4j.log;

/**
 * The <code>Log4jLogFactory</code> implements a SNMP4J LogFactory for
 * Log4J. In order to use Log4J for logging SNMP4J log messages the
 * static {@link LogFactory#setLogFactory} method has to be used before
 * any SNMP4J class is referenced or instantiated.
 *
 * @author Frank Fock
 * @version 1.7
 * @since 1.6
 */
public class ConsoleLogFactory extends LogFactory {

  public ConsoleLogFactory() {
  }

  protected LogAdapter createLogger(Class c) {
    return new ConsoleLogAdapter();
  }

  protected LogAdapter createLogger(String className) {
    return new ConsoleLogAdapter();
  }

}
