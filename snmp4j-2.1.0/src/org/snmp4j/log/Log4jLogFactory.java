/*_############################################################################
  _## 
  _##  SNMP4J 2 - Log4jLogFactory.java  
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

import org.apache.log4j.Logger;
import java.util.Iterator;
import java.util.Collections;
import java.util.ArrayList;

/**
 * The <code>Log4jLogFactory</code> implements a SNMP4J LogFactory for
 * Log4J. In order to use Log4J for logging SNMP4J log messages the
 * static {@link LogFactory#setLogFactory} method has to be used before
 * any SNMP4J class is referenced or instantiated.
 *
 * @author Frank Fock
 * @version 1.6.1
 * @since 1.2.1
 */
public class Log4jLogFactory extends LogFactory {

  public Log4jLogFactory() {
  }

  protected LogAdapter createLogger(Class c) {
    return new Log4jLogAdapter(Logger.getLogger(c));
  }

  protected LogAdapter createLogger(String className) {
    return new Log4jLogAdapter(Logger.getLogger(className));
  }

  public LogAdapter getRootLogger() {
    return new Log4jLogAdapter(Logger.getRootLogger());
  }

  public Iterator loggers() {
    ArrayList<Logger> l = Collections.<Logger>list(Logger.getRootLogger().
                                                   getLoggerRepository().
                                                   getCurrentLoggers());
    ArrayList<Log4jLogAdapter> la = new ArrayList<Log4jLogAdapter>(l.size());
    for (Logger logger : l) {
      la.add(new Log4jLogAdapter(logger));
    }
    Collections.sort(la);
    return la.iterator();
  }
}
