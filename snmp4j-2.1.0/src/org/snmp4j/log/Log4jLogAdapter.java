/*_############################################################################
  _## 
  _##  SNMP4J 2 - Log4jLogAdapter.java  
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

import org.apache.log4j.*;

import java.io.Serializable;
import java.util.Iterator;
import java.util.logging.Handler;

import org.snmp4j.util.EnumerationIterator;

/**
 * The <code>Log4jLogAdapter</code> implements a logging adapter for Log4J.
 *
 * @author Frank Fock
 * @version 1.10
 * @since 1.2.1
 */
public class Log4jLogAdapter implements LogAdapter, Comparable {

  private final Logger logger;
  private final static String FQCN = Log4jLogAdapter.class.getName();

  /**
   * Creates a Log4J log adapter from a Log4J Logger.
   * @param logger
   *    the Log4J Logger to use with this adapter.
   * @since 1.2.1
   */
  public Log4jLogAdapter(Logger logger) {
    this.logger = logger;
  }

  /**
   * Logs a debug message.
   *
   * @param message the message to log.
   */
  public void debug(Serializable message) {
    logger.log(FQCN, Level.DEBUG, message, null);
  }

  /**
   * Logs an error message.
   *
   * @param message the message to log.
   */
  public void error(Serializable message) {
    logger.log(FQCN, Level.ERROR, message, null);
  }

  /**
   * Logs an error message.
   *
   * @param message the message to log.
   * @param throwable the exception that caused to error.
   */
  public void error(CharSequence message, Throwable throwable) {
    logger.log(FQCN, Level.ERROR, message, throwable);
  }

  /**
   * Logs an informational message.
   *
   * @param message the message to log.
   */
  public void info(CharSequence message) {
    logger.log(FQCN, Level.INFO, message, null);
  }

  /**
   * Checks whether DEBUG level logging is activated for this log adapter.
   *
   * @return <code>true</code> if logging is enabled or <code>false</code>
   *   otherwise.
   */
  public boolean isDebugEnabled() {
    return logger.isDebugEnabled();
  }

  /**
   * Checks whether INFO level logging is activated for this log adapter.
   *
   * @return <code>true</code> if logging is enabled or <code>false</code>
   *   otherwise.
   */
  public boolean isInfoEnabled() {
    return logger.isInfoEnabled();
  }

  /**
   * Checks whether WARN level logging is activated for this log adapter.
   *
   * @return <code>true</code> if logging is enabled or <code>false</code>
   *   otherwise.
   */
  public boolean isWarnEnabled() {
    return logger.isEnabledFor(Level.WARN);
  }

  /**
   * Logs an warning message.
   *
   * @param message the message to log.
   */
  public void warn(Serializable message) {
    logger.log(FQCN, Level.WARN, message, null);
  }

  public void fatal(Object message) {
    logger.log(FQCN, Level.FATAL, message, null);
  }

  public void fatal(CharSequence message, Throwable throwable) {
    logger.log(FQCN, Level.FATAL, message, throwable);
  }

  public void setLogLevel(LogLevel level) {
    Level l;
    switch (level.getLevel()) {
      case LogLevel.LEVEL_OFF:
        l = Level.OFF;
        break;
      case LogLevel.LEVEL_ALL:
        l = Level.ALL;
        break;
      case LogLevel.LEVEL_TRACE:
        l = Level.DEBUG;
        break;
      case LogLevel.LEVEL_DEBUG:
        l = Level.DEBUG;
        break;
      case LogLevel.LEVEL_INFO:
        l = Level.INFO;
        break;
      case LogLevel.LEVEL_WARN:
        l = Level.WARN;
        break;
      case LogLevel.LEVEL_ERROR:
        l = Level.ERROR;
        break;
      case LogLevel.LEVEL_FATAL:
        l = Level.FATAL;
        break;
      default:
        l = null;
    }
    logger.setLevel(l);
  }

  public Logger getLogger() {
    return logger;
  }

  public String getName() {
    return logger.getName();
  }

  public LogLevel getLogLevel() {
    Level l = logger.getLevel();
    return toLogLevel(l);
  }

  private LogLevel toLogLevel(Level l) {
    if (l == null) {
      return LogLevel.NONE;
    }
    switch (l.toInt()) {
      case Level.OFF_INT:
        return LogLevel.OFF;
      case Level.ALL_INT:
        return LogLevel.ALL;
      case Level.DEBUG_INT:
        return LogLevel.DEBUG;
      case Level.INFO_INT:
        return LogLevel.INFO;
      case Level.WARN_INT:
        return LogLevel.WARN;
      case Level.ERROR_INT:
        return LogLevel.ERROR;
      case Level.FATAL_INT:
        return LogLevel.FATAL;
    }
    return LogLevel.DEBUG;
  }

  public int compareTo(Object o) {
    return getName().compareTo(((Log4jLogAdapter)o).getName());
  }

  public LogLevel getEffectiveLogLevel() {
    Level l = logger.getEffectiveLevel();
    return toLogLevel(l);
  }

  public Iterator<Appender> getLogHandler() {
    return new EnumerationIterator<Appender>(logger.getAllAppenders());
  }
}
