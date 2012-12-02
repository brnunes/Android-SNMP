/*_############################################################################
  _## 
  _##  SNMP4J 2 - WorkerTask.java  
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
package org.snmp4j.util;

/**
 * This models a <code>WorkerTask</code> instance that would be executed by a
 * {@link WorkerPool} upon submission.
 *
 * @author Frank Fock
 * @version 1.9
 * @since 1.9
 */
public interface WorkerTask extends Runnable {

  /**
   * The <code>WorkerPool</code> might call this method to hint the active
   * <code>WorkTask</code> instance to complete execution as soon as possible.
   */
  void terminate();

  /**
   * Waits until this task has been finished.
   */
  void join() throws InterruptedException;

  /**
   * Interrupts this task.
   * @see Thread#interrupt()
   */
  void interrupt();

}
