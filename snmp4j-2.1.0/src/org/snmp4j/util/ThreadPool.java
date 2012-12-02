/*_############################################################################
  _## 
  _##  SNMP4J 2 - ThreadPool.java  
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

import java.util.*;

/**
 * The <code>ThreadPool</code> provides a pool of a fixed number of threads
 * that are capable to execute tasks that implement the <code>Runnable</code>
 * interface concurrently. The ThreadPool blocks when all threads are busy
 * with tasks and an additional task is added.
 *
 * @author Frank Fock
 * @version 1.6
 * @since 1.0.2
 */
public class ThreadPool implements WorkerPool {

  protected Vector<TaskManager> taskManagers;
  protected String name = "ThreadPool";
  protected volatile boolean stop = false;
  protected boolean respawnThreads = false;

  protected ThreadPool() {
  }

  protected String getTaskManagerName(String prefix, int index) {
    return prefix+"."+index;
  }

  protected void setup(String name, int size) {
    this.name = name;
    taskManagers = new Vector<TaskManager>(size);
    for (int i=0; i<size; i++) {
      TaskManager tm = new TaskManager(getTaskManagerName(name, i));
      taskManagers.add(tm);
      tm.start();
    }
  }

  /**
   * Creates a thread pool with the supplied name and size.
   * @param name
   *    the name prefix for the threads in this pool.
   * @param size
   *    the number of threads in this pool. This number also specifies the
   *    number of concurrent tasks that can be executed with this pool.
   * @return
   *    a <code>ThreadPool</code> instance.
   */
  public static ThreadPool create(String name, int size) {
    ThreadPool pool = new ThreadPool();
    pool.setup(name, size);
    return pool;
  }

  /**
   * Executes a task on behalf of this thread pool. If all threads are currently
   * busy, this method call blocks until a thread gets idle again which is when
   * the call returns immediately.
   * @param task
   *    a <code>Runnable</code> to execute.
   */
  public synchronized void execute(WorkerTask task) {
    while (true) {
      for (int i=0; i<taskManagers.size(); i++) {
        TaskManager tm = taskManagers.get(i);
        if ((respawnThreads) && (!tm.isAlive())) {
          tm = new TaskManager(getTaskManagerName(name, i));
        }
        if (tm.isIdle()) {
          tm.execute(task);
          return;
        }
      }
      try {
        wait();
      }
      catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
      }
    }
  }

  /**
   * Tries to execute a task on behalf of this thread pool. If all threads are
   * currently busy, this method returns <code>false</code>. Otherwise the task
   * is executed in background.
   * @param task
   *    a <code>Runnable</code> to execute.
   * @return
   *    <code>true</code> if the task is executing.
   * @since 1.6
   */
  public synchronized boolean tryToExecute(WorkerTask task) {
    for (int i=0; i<taskManagers.size(); i++) {
      TaskManager tm = taskManagers.get(i);
      if ((respawnThreads) && (!tm.isAlive())) {
        tm = new TaskManager(getTaskManagerName(name, i));
      }
      if (tm.isIdle()) {
        tm.execute(task);
        return true;
      }
    }
    return false;
  }

  /**
   * Tests if the threads are respawn (recreates) when they have been stopped
   * or canceled.
   * @return
   *    <code>true</code> if threads are respawn.
   */
  public boolean isRespawnThreads() {
    return respawnThreads;
  }

  /**
   * Specifies whether threads are respawned by this thread pool after they
   * have been stopped or not. Default is no respawning.
   * @param respawnThreads
   *    if <code>true</code> then threads will be respawn.
   */
  public void setRespawnThreads(boolean respawnThreads) {
    this.respawnThreads = respawnThreads;
  }

  /**
   * Returns the name of the thread pool.
   * @return
   *    the name of this thread pool.
   */
  public String getName() {
    return name;
  }

  /**
   * Stops all threads in this thread pool gracefully. This method will not
   * return until all threads have been terminated and joined successfully.
   */
  public void stop() {
    List<? extends TaskManager> tms;
    synchronized (this) {
      stop = true;
      tms = (List<? extends TaskManager>) taskManagers.clone();
    }
    for (int i=0; i<tms.size(); i++) {
      TaskManager tm = tms.get(i);
      tm.terminate();
      synchronized (tm) {
        tm.notify();
      }
      try {
        tm.join();
      }
      catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
      }
    }
  }

  /**
   * Cancels all threads non-blocking by interrupting them.
   */
  public synchronized void cancel() {
    stop = true;
    for (int i=0; i<taskManagers.size(); i++) {
      TaskManager tm = taskManagers.get(i);
      tm.terminate();
      tm.interrupt();
    }
  }

  /**
   * Interrupts all threads in the pool.
   * @since 1.6
   */
  public synchronized void interrupt() {
    for (int i=0; i<taskManagers.size(); i++) {
      TaskManager tm = taskManagers.get(i);
      tm.interrupt();
    }
  }

  /**
   * Checks if all threads of the pool are idle.
   * @return
   *    <code>true</code> if all threads are idle.
   * @since 1.6
   */
  public synchronized boolean isIdle() {
    for (int i=0; i<taskManagers.size(); i++) {
      TaskManager tm = taskManagers.get(i);
      if (!tm.isIdle()) {
        return false;
      }
    }
    return true;
  }

  /**
   * The <code>TaskManager</code> executes tasks in a thread.
   *
   * @author Frank Fock
   * @version 1.9
   * @since 1.0.2
   */
  class TaskManager extends Thread {

    private WorkerTask task = null;
    private volatile boolean run = true;

    public TaskManager(String name) {
      super(name);
    }

    public synchronized void run() {
      while ((!stop) && run) {
        if (task != null) {
          task.run();
          synchronized (ThreadPool.this) {
            task = null;
            ThreadPool.this.notify();
          }
        }
        else {
          try {
            wait();
          }
          catch (InterruptedException ex) {
            run = respawnThreads;
            break;
          }
        }
      }
    }

    public boolean isIdle() {
      return ((task == null) && run);
    }

    public boolean isStopped() {
      return stop;
    }

    public void terminate() {
      stop = true;
      WorkerTask t;
      if ((t = task) != null) {
        t.terminate();
      }
    }

    public synchronized void execute(WorkerTask task) {
      if (this.task == null) {
        this.task = task;
        notify();
      }
      else {
        throw new IllegalStateException("TaskManager is not idle");
      }
    }
  }
}
