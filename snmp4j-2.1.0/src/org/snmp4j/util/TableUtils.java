/*_############################################################################
  _## 
  _##  SNMP4J 2 - TableUtils.java  
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

import org.snmp4j.log.*;
import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import java.io.*;

/**
 * The <code>TableUtils</code> class provides utility functions to retrieve
 * SNMP tabular data.
 *
 * @author Frank Fock
 * @version 1.6e
 * @since 1.0.2
 */
public class TableUtils extends AbstractSnmpUtility {

  private static final LogAdapter logger =
      LogFactory.getLogger(TableUtils.class);

  // RowStatus TC enumerated values
  public static final int ROWSTATUS_ACTIVE = 1;
  public static final int ROWSTATUS_NOTINSERVICE = 2;
  public static final int ROWSTATUS_NOTREADY = 3;
  public static final int ROWSTATUS_CREATEANDGO = 4;
  public static final int ROWSTATUS_CREATEANDWAIT = 5;
  public static final int ROWSTATUS_DESTROY = 6;

  private int maxNumOfRowsPerPDU = 10;
  private int maxNumColumnsPerPDU = 10;

  /**
   * Creates a <code>TableUtils</code> instance. The created instance is thread
   * safe as long as the supplied <code>Session</code> and <code>PDUFactory</code>
   * are thread safe.
   *
   * @param snmpSession
   *    a SNMP <code>Session</code> instance.
   * @param pduFactory
   *    a <code>PDUFactory</code> instance that creates the PDU that are used
   *    by this instance to retrieve table data using GETBULK/GETNEXT
   *    operations.
   */
  public TableUtils(Session snmpSession, PDUFactory pduFactory) {
    super(snmpSession, pduFactory);
  }

  /**
   * Gets synchronously SNMP tabular data from one or more tables.
   * The data is returned row-by-row as a list of {@link TableEvent} instances.
   * Each instance represents a row (or an error condition). Besides the
   * target agent, the OIDs of the columnar objects have to be specified
   * for which instances should be retrieved. With a lower bound index and
   * an upper bound index, the result set can be narrowed to improve
   * performance. This method can be executed concurrently by multiple threads.
   *
   * @param target
   *    a <code>Target</code> instance.
   * @param columnOIDs
   *    an array of OIDs of the columnar objects whose instances should be
   *    retrieved. The columnar objects may belong to different tables.
   *    Typically they belong to tables that share a common index or sub-index
   *    prefix. Note: The result of this method is not defined if instance OIDs
   *    are supplied in this array!
   * @param lowerBoundIndex
   *    an optional parameter that specifies the lower bound index.
   *    If not <code>null</code>, all returned rows have an index greater than
   *    <code>lowerBoundIndex</code>.
   * @param upperBoundIndex
   *    an optional parameter that specifies the upper bound index.
   *    If not <code>null</code>, all returned rows have an index less or equal
   *    than <code>upperBoundIndex</code>.
   * @return
   *    a <code>List</code> of {@link TableEvent} instances. Each instance
   *    represents successfully retrieved row or an error condition. Error
   *    conditions (any status other than {@link TableEvent#STATUS_OK})
   *    may only appear at the last element of the list.
   */
  public List<TableEvent> getTable(Target target,
                       OID[] columnOIDs,
                       OID lowerBoundIndex,
                       OID upperBoundIndex) {

    if ((columnOIDs == null) || (columnOIDs.length == 0)) {
      throw new IllegalArgumentException("No column OIDs specified");
    }
    InternalTableListener listener = new InternalTableListener();
    TableRequest req = createTableRequest(target, columnOIDs, listener,
                                          null,
                                          lowerBoundIndex,
                                          upperBoundIndex);
    synchronized (listener) {
      if (req.sendNextChunk()) {
        try {
          while (!listener.isFinished()) {
            listener.wait();
          }
        }
        catch (InterruptedException ex) {
          Thread.currentThread().interrupt();
        }
      }
    }
    return listener.getRows();
  }

  protected TableRequest createTableRequest(Target target, OID[] columnOIDs,
                                            TableListener listener,
                                            Object userObject,
                                            OID lowerBoundIndex,
                                            OID upperBoundIndex) {
    return new TableRequest(target, columnOIDs, listener,
                            userObject, lowerBoundIndex, upperBoundIndex);
  }

  /**
   * Gets SNMP tabular data from one or more tables. The data is returned
   * asynchronously row-by-row through a supplied callback. Besides the
   * target agent, the OIDs of the columnar objects have to be specified
   * for which instances should be retrieved. With a lower bound index and
   * an upper bound index, the result set can be narrowed to improve
   * performance.
   * <p>
   * This method may call the {@link TableListener#finished} method before
   * it returns. If you want to synchronize the main thread with the
   * finishing of the table retrieval, follow this pattern:
   * <pre>
   *      synchronized (this) {
   *         TableListener myListener = ... {
   *            private boolean finished;
   *
   *            public boolean isFinished() {
   *              return finished;
   *            }
   *
   *            public void finished(TableEvent event) {
   *               ..
   *               finished = true;
   *               synchronized (event.getUserObject()) {
   *                  event.getUserObject().notify();
   *               }
   *            }
   *         };
   *         tableUtil.getTable(..,..,myListener,this,..,..);
   *         while (!myListener.isFinished()) {
   *           wait();
   *         }
   *      }
   * </pre>
   *
   * @param target
   *    a <code>Target</code> instance.
   * @param columnOIDs
   *    an array of OIDs of the columnar objects whose instances should be
   *    retrieved. The columnar objects may belong to different tables.
   *    Typically they belong to tables that share a common index or sub-index
   *    prefix. Note: The result of this method is not defined if instance OIDs
   *    are supplied in this array!
   * @param listener
   *    a <code>TableListener</code> that is called with {@link TableEvent}
   *    objects when an error occured, new rows have been retrieved, or when
   *    the table has been retrieved completely.
   * @param userObject
   *    an user object that is transparently supplied to the above call back.
   * @param lowerBoundIndex
   *    an optional parameter that specifies the lower bound index.
   *    If not <code>null</code>, all returned rows have an index greater than
   *    <code>lowerBoundIndex</code>.
   * @param upperBoundIndex
   *    an optional parameter that specifies the upper bound index.
   *    If not <code>null</code>, all returned rows have an index less or equal
   *    than <code>upperBoundIndex</code>.
   */
  public void getTable(Target target,
                       OID[] columnOIDs,
                       TableListener listener,
                       Object userObject,
                       OID lowerBoundIndex,
                       OID upperBoundIndex) {
    if ((columnOIDs == null) || (columnOIDs.length == 0)) {
      throw new IllegalArgumentException("No column OIDs specified");
    }
    TableRequest req = new TableRequest(target, columnOIDs, listener,
                                        userObject,
                                        lowerBoundIndex,
                                        upperBoundIndex);
    req.sendNextChunk();
  }

  /**
   * Gets SNMP tabular data from one or more tables. The data is returned
   * asynchronously row-by-row through a supplied callback. Besides the
   * target agent, the OIDs of the columnar objects have to be specified
   * for which instances should be retrieved. With a lower bound index and
   * an upper bound index, the result set can be narrowed to improve
   * performance.
   * <p>
   * This implementation must not be used with sparese tables, because it
   * is optimized for dense tables and will not return correct results for
   * sparse tables.
   * </p>
   *
   * @param target
   *    a <code>Target</code> instance.
   * @param columnOIDs
   *    an array of OIDs of the columnar objects whose instances should be
   *    retrieved. The columnar objects may belong to different tables.
   *    Typically they belong to tables that share a common index or sub-index
   *    prefix. Note: The result of this method is not defined if instance OIDs
   *    are supplied in this array!
   * @param listener
   *    a <code>TableListener</code> that is called with {@link TableEvent}
   *    objects when an error occured, new rows have been retrieved, or when
   *    the table has been retrieved completely.
   * @param userObject
   *    an user object that is transparently supplied to the above call back.
   * @param lowerBoundIndex
   *    an optional parameter that specifies the lower bound index.
   *    If not <code>null</code>, all returned rows have an index greater than
   *    <code>lowerBoundIndex</code>.
   * @param upperBoundIndex
   *    an optional parameter that specifies the upper bound index.
   *    If not <code>null</code>, all returned rows have an index less or equal
   *    than <code>lowerBoundIndex</code>.
   * @since 1.5
   */
  public void getDenseTable(Target target,
                            OID[] columnOIDs,
                            TableListener listener,
                            Object userObject,
                            OID lowerBoundIndex,
                            OID upperBoundIndex) {
    if ((columnOIDs == null) || (columnOIDs.length == 0)) {
      throw new IllegalArgumentException("No column OIDs specified");
    }
    TableRequest req = new TableRequest(target, columnOIDs, listener,
                                        userObject,
                                        lowerBoundIndex,
                                        upperBoundIndex);
    req.sendNextChunk();
  }

  /**
   * Gets the maximum number of rows that will be retrieved per SNMP GETBULK
   * request.
   *
   * @return
   *    an integer greater than zero that specifies the maximum number of rows
   *    to retrieve per SNMP GETBULK operation.
   */
  public int getMaxNumRowsPerPDU() {
    return maxNumOfRowsPerPDU;
  }

  /**
   * Sets the maximum number of rows that will be retrieved per SNMP GETBULK
   * request. The default is 10.
   *
   * @param numberOfRowsPerChunk
   *    an integer greater than zero that specifies the maximum number of rows
   *    to retrieve per SNMP GETBULK operation.
   */
  public void setMaxNumRowsPerPDU(int numberOfRowsPerChunk) {
    if (numberOfRowsPerChunk < 1) {
      throw new IllegalArgumentException(
          "The number of rows per PDU must be > 0");
    }
    this.maxNumOfRowsPerPDU = numberOfRowsPerChunk;
  }

  /**
   * Gets the maximum number of columns that will be retrieved per SNMP GETNEXT
   * or GETBULK request.
   *
   * @return
   *    an integer greater than zero that specifies the maximum columns of rows
   *    to retrieve per SNMP GETNEXT or GETBULK operation.
   */
  public int getMaxNumColumnsPerPDU() {
    return maxNumColumnsPerPDU;
  }

  /**
   * Sets the maximum number of columns that will be retrieved per SNMP GETNEXT
   * or GETBULK request. The default is 10.
   *
   * @param numberOfColumnsPerChunk
   *    an integer greater than zero that specifies the maximum columns of rows
   *    to retrieve per SNMP GETNEXT or GETBULK operation.
   */
  public void setMaxNumColumnsPerPDU(int numberOfColumnsPerChunk) {
    if (numberOfColumnsPerChunk < 1) {
      throw new IllegalArgumentException(
          "The number of columns per PDU must be > 0");
    }
    this.maxNumColumnsPerPDU = numberOfColumnsPerChunk;
  }

  public class TableRequest implements ResponseListener {

    Target target;
    OID[] columnOIDs;
    TableListener listener;
    Object userObject;
    OID lowerBoundIndex;
    OID upperBoundIndex;

    private int sent = 0;
    private boolean anyMatch = false;
    private Vector<OID> lastSent = null;
    private LinkedList<Row> rowCache = new LinkedList<Row>();
    protected Vector<OID> lastReceived;

    volatile boolean finished = false;

    public TableRequest(Target target,
                        OID[] columnOIDs,
                        TableListener listener,
                        Object userObject,
                        OID lowerBoundIndex,
                        OID upperBoundIndex) {
      this.target = target;
      this.columnOIDs = columnOIDs;
      this.listener = listener;
      this.userObject = userObject;
      this.lastReceived = new Vector<OID>(Arrays.asList(columnOIDs));
      this.upperBoundIndex = upperBoundIndex;
      this.lowerBoundIndex = lowerBoundIndex;
      if (lowerBoundIndex != null) {
        for (int i = 0; i < lastReceived.size(); i++) {
          OID oid = new OID((lastReceived.get(i)));
          oid.append(lowerBoundIndex);
          lastReceived.set(i, oid);
        }
      }
    }

    public boolean sendNextChunk() {
      if (sent >= lastReceived.size()) {
        return false;
      }
      PDU pdu = pduFactory.createPDU(target);
      if (target.getVersion() == SnmpConstants.version1) {
        pdu.setType(PDU.GETNEXT);
      }
      else if (pdu.getType() != PDU.GETNEXT) {
        pdu.setType(PDU.GETBULK);
      }
      int sz = Math.min(lastReceived.size() - sent, maxNumColumnsPerPDU);
      if (pdu.getType() == PDU.GETBULK) {
        if (maxNumOfRowsPerPDU > 0) {
          pdu.setMaxRepetitions(maxNumOfRowsPerPDU);
          pdu.setNonRepeaters(0);
        }
        else {
          pdu.setNonRepeaters(sz);
          pdu.setMaxRepetitions(0);
        }
      }
      lastSent = new Vector<OID>(sz + 1);
      for (int i = sent; i < sent + sz; i++) {
        OID col = lastReceived.get(i);
        VariableBinding vb = new VariableBinding(col);
        pdu.add(vb);
        if (pdu.getBERLength() > target.getMaxSizeRequestPDU()) {
          pdu.trim();
          break;
        }
        else {
          lastSent.add(lastReceived.get(i));
        }
      }
      try {
        Integer startCol = sent;
        sent += pdu.size();
        sendRequest(pdu, target, startCol);
      }
      catch (Exception ex) {
        logger.error(ex);
        if (logger.isDebugEnabled()) {
          ex.printStackTrace();
        }
        listener.finished(new TableEvent(this, userObject, ex));
        return false;
      }
      return true;
    }

    protected void sendRequest(PDU pdu, Target target, Integer startCol)
        throws IOException
    {
      session.send(pdu, target, startCol, this);
    }

    public void onResponse(ResponseEvent event) {
      // Do not forget to cancel the asynchronous request! ;-)
      session.cancel(event.getRequest(), this);
      if (finished) {
        return;
      }
      synchronized (this) {
        if (checkResponse(event)) {
          boolean anyMatchInChunk = false;
          int startCol = (Integer) event.getUserObject();
          PDU request = event.getRequest();
          PDU response = event.getResponse();
          int cols = request.size();
          int rows = response.size() / cols;
          OID lastMinIndex = null;
          for (int r = 0; r < rows; r++) {
            Row row = null;
            anyMatchInChunk = false;
            for (int c = 0; c < request.size(); c++) {
              int pos = startCol + c;
              VariableBinding vb = response.get(r * cols + c);
              if (vb.isException()) {
                continue;
              }
              OID id = vb.getOid();
              OID col = columnOIDs[pos];
              if (id.startsWith(col)) {
                OID index =
                    new OID(id.getValue(), col.size(), id.size() - col.size());
                if ((upperBoundIndex != null) &&
                    (index.compareTo(upperBoundIndex) > 0)) {
                  continue;
                }
                if ((lastMinIndex == null) ||
                    (index.compareTo(lastMinIndex) < 0)) {
                  lastMinIndex = index;
                }
                anyMatchInChunk = true;
                if ((row == null) || (!row.getRowIndex().equals(index))) {
                  row = null;
                  for (ListIterator<Row> it = rowCache.listIterator(rowCache.size());
                       it.hasPrevious(); ) {
                    Row lastRow = it.previous();
                    int compareResult = index.compareTo(lastRow.getRowIndex());
                    if (compareResult == 0) {
                      row = lastRow;
                      break;
                    }
                    else if (compareResult > 0) {
                      break;
                    }
                  }
                }
                if (row == null) {
                  row = new Row(index);
                  if (rowCache.size() == 0) {
                    rowCache.add(row);
                  }
                  else if ((rowCache.getFirst()).getRowIndex().compareTo(
                      index) >= 0) {
                    rowCache.addFirst(row);
                  }
                  else {
                    for (ListIterator<Row> it = rowCache.listIterator(rowCache.size());
                         it.hasPrevious(); ) {
                      Row lastRow = it.previous();
                      if (index.compareTo(lastRow.index) >= 0) {
                        it.set(row);
                        it.add(lastRow);
                        break;
                      }
                    }
                  }
                }
                if (((!row.setNumComplete(pos)) ||
                     (row.size() > pos)) && (row.get(pos) != null)) {
                  finished = true;
                  listener.finished(new TableEvent(this, userObject,
                      TableEvent.STATUS_WRONG_ORDER));
                  return;
                }
                row.setNumComplete(pos);
                if (pos < row.getNumComplete()) {
                  row.set(pos, vb);
                }
                else {
                  row.add(vb);
                }
                lastReceived.set(pos, vb.getOid());
              }
            }
          }
          anyMatch |= anyMatchInChunk;
          while ((rowCache.size() > 0) &&
                 ((rowCache.getFirst()).getNumComplete() ==
                  columnOIDs.length) &&
                 ((lastMinIndex == null) ||
                  ((rowCache.getFirst()).getRowIndex().compareTo(
                      lastMinIndex) < 0))) {
            if (!listener.next(getTableEvent())) {
              finished = true;
              listener.finished(new TableEvent(this, userObject));
              return;
            }
          }
          if (!sendNextChunk()) {
            if (anyMatch) {
              sent = 0;
              anyMatch = false;
              sendNextChunk();
            }
            else {
              emptyCache();
              finished = true;
              listener.finished(new TableEvent(this, userObject));
            }
          }
        }
      }
    }

    protected boolean checkResponse(ResponseEvent event) {
      if (event.getError() != null) {
        finished = true;
        emptyCache();
        listener.finished(new TableEvent(this, userObject, event.getError()));
      }
      else if (event.getResponse() == null) {
        finished = true;
        // timeout
        emptyCache();
        listener.finished(new TableEvent(this, userObject,
                                         TableEvent.STATUS_TIMEOUT));
      }
      else if (event.getResponse().getType() == PDU.REPORT) {
        finished = true;
        emptyCache();
        listener.finished(new TableEvent(this, userObject,
                                         event.getResponse()));
      }
      else if (event.getResponse().getErrorStatus() != PDU.noError) {
        finished = true;
        emptyCache();
        listener.finished(new TableEvent(this, userObject,
                                         event.getResponse().getErrorStatus()));
      }
      else {
        return true;
      }
      return false;
    }

    private void emptyCache() {
      while (rowCache.size() > 0) {
        if (!listener.next(getTableEvent())) {
          break;
        }
      }
    }

    private TableEvent getTableEvent() {
      Row r = rowCache.removeFirst();
      r.setNumComplete(columnOIDs.length);
      VariableBinding[] vbs = new VariableBinding[r.size()];
      r.copyInto(vbs);
      return new TableEvent(this, userObject, r.getRowIndex(), vbs);
    }

    public Row getRow(OID index) {
      for (ListIterator<Row> it = rowCache.listIterator(rowCache.size() + 1);
           it.hasPrevious(); ) {
        Row r = it.previous();
        if (index.equals(r.getRowIndex())) {
          return r;
        }
      }
      return null;
    }
  }

  /**
   * The <code>DenseTableRequest</code> extends TableRequest to implement a
   * faster table retrieval than the original. Caution:
   * This version does not correctly retrieve sparse tables!
   *
   * @author Frank Fock
   * @since 1.5
   */
  class DenseTableRequest extends TableRequest {
    protected DenseTableRequest(Target target,
                                OID[] columnOIDs,
                                TableListener listener,
                                Object userObject,
                                OID lowerBoundIndex,
                                OID upperBoundIndex) {
      super(target, columnOIDs, listener, userObject, lowerBoundIndex,
            upperBoundIndex);
    }

    public synchronized void onResponse(ResponseEvent event) {
      // Do not forget to cancel the asynchronous request! ;-)
      session.cancel(event.getRequest(), this);
      if (finished) {
        return;
      }
      if (checkResponse(event)) {
        int startCol = ((Integer) event.getUserObject()).intValue();
        PDU request = event.getRequest();
        PDU response = event.getResponse();
        int cols = request.size();
        int rows = response.size() / cols;
        OID lastMinIndex = null;
        for (int r = 0; r < rows; r++) {
          Row row = null;
          for (int c = 0; c < request.size(); c++) {
            int pos = startCol + c;
            VariableBinding vb = response.get(r * cols + c);
            if (vb.isException()) {
              continue;
            }
            OID id = vb.getOid();
            OID col = columnOIDs[pos];
            if (id.startsWith(col)) {
              OID index =
                  new OID(id.getValue(), col.size(), id.size() - col.size());
              if ((upperBoundIndex != null) &&
                  (index.compareTo(upperBoundIndex) > 0)) {
                continue;
              }
              if ((lastMinIndex == null) ||
                  (index.compareTo(lastMinIndex) < 0)) {
                lastMinIndex = index;
              }
              if (row == null) {
                row = new Row(index);
              }
              row.setNumComplete(pos);
              if (pos < row.getNumComplete()) {
                row.set(pos, vb);
              }
              else {
                row.add(vb);
              }
              lastReceived.set(pos, vb.getOid());
            }
          }
          if (row != null) {
            if (!listener.next(new TableEvent(this, userObject, row.getRowIndex(),
                                              (VariableBinding[])
                                              row.toArray(new VariableBinding[0])))) {
              finished = true;
              listener.finished(new TableEvent(this, userObject));
              return;
            }
          }
        }
        if (!sendNextChunk()) {
          finished = true;
          listener.finished(new TableEvent(this, userObject));
        }
      }
    }
  }

  /**
   * Creates a SNMP table row for a table that supports the RowStatus
   * mechanism for row creation.
   * @param target
   *    the Target SNMP entity for the operation.
   * @param rowStatusColumnOID
   *    the column OID of the RowStatus column (without any instance identifier).
   * @param rowIndex
   *    the OID denoting the index of the table row to create.
   * @param values
   *    the values of columns to set in the row. If <code>values</code> is
   *    <code>null</code> the row is created via the tripple mode row creation
   *    mechanism (RowStatus is set to createAndWait). Otherwise, each variable
   *    binding has to contain the OID of the columnar object ID (without any
   *    instance identifier) and its value. On return, the variable bindings
   *    will be modified so that the variable binding OIDs will contain the
   *    instance OIDs of the respective columns (thus column OID + rowIndex).
   * @return ResponseEvent
   *    the ResponseEvent instance returned by the SNMP session on response
   *    of the internally sent SET request. If <code>null</code>, an IO
   *    exception has occurred. Otherwise, if the response PDU is
   *    <code>null</code> a timeout has occured, Otherwise, check the error
   *    status for {@link SnmpConstants#SNMP_ERROR_SUCCESS} to verify that the
   *    row creation was successful.
   * @since 1.6
   */
  public ResponseEvent createRow(Target target,
                                 OID rowStatusColumnOID, OID rowIndex,
                                 VariableBinding[] values) {
    PDU pdu = pduFactory.createPDU(target);
    OID rowStatusID = new OID(rowStatusColumnOID);
    rowStatusID.append(rowIndex);
    VariableBinding rowStatus = new VariableBinding(rowStatusID);
    if (values != null) {
      // one-shot mode
      rowStatus.setVariable(new Integer32(ROWSTATUS_CREATEANDGO));
    }
    else {
      rowStatus.setVariable(new Integer32(ROWSTATUS_CREATEANDWAIT));
    }
    pdu.add(rowStatus);
    if (values != null) {
      // append index to all columnar values
      for (int i = 0; i < values.length; i++) {
        OID columnOID = new OID(values[i].getOid());
        columnOID.append(rowIndex);
        values[i].setOid(columnOID);
      }
      pdu.addAll(values);
    }
    pdu.setType(PDU.SET);
    try {
      ResponseEvent responseEvent = session.send(pdu, target);
      return responseEvent;
    }
    catch (IOException ex) {
      logger.error(ex);
    }
    return null;
  }

  /**
   * Destroys a SNMP table row from a table that support the RowStatus
   * mechanism for row creation/deletion.
   * @param target
   *    the Target SNMP entity for the operation.
   * @param rowStatusColumnOID
   *    the column OID of the RowStatus column (without any instance identifier).
   * @param rowIndex
   *    the OID denoting the index of the table row to destroy.
   * @return ResponseEvent
   *    the ResponseEvent instance returned by the SNMP session on response
   *    of the internally sent SET request. If <code>null</code>, an IO
   *    exception has occurred. Otherwise, if the response PDU is
   *    <code>null</code> a timeout has occured, Otherwise, check the error
   *    status for {@link SnmpConstants#SNMP_ERROR_SUCCESS} to verify that the
   *    row creation was successful.
   * @since 1.7.6
   */
  public ResponseEvent destroyRow(Target target,
                                  OID rowStatusColumnOID, OID rowIndex) {
    PDU pdu = pduFactory.createPDU(target);
    OID rowStatusID = new OID(rowStatusColumnOID);
    rowStatusID.append(rowIndex);
    VariableBinding rowStatus = new VariableBinding(rowStatusID);
    rowStatus.setVariable(new Integer32(ROWSTATUS_DESTROY));
    pdu.add(rowStatus);
    pdu.setType(PDU.SET);
    try {
      ResponseEvent responseEvent = session.send(pdu, target);
      return responseEvent;
    }
    catch (IOException ex) {
      logger.error(ex);
    }
    return null;
  }

  class Row extends Vector {

    private static final long serialVersionUID = -2297277440117636627L;

    private OID index;

    public Row(OID index) {
      super();
      this.index = index;
    }

    public OID getRowIndex() {
      return index;
    }

    public int getNumComplete() {
      return super.size();
    }

    public boolean setNumComplete(int numberOfColumnsComplete) {
      int sz = numberOfColumnsComplete - getNumComplete();
      for (int i = 0; i < sz; i++) {
        super.add(null);
      }
      return (sz >= 0);
    }
  }

  class InternalTableListener implements TableListener {

    private List<TableEvent> rows = new LinkedList<TableEvent>();
    private volatile boolean finished = false;

    public boolean next(TableEvent event) {
      rows.add(event);
      return true;
    }

    public synchronized void finished(TableEvent event) {
      if ((event.getStatus() != TableEvent.STATUS_OK) ||
          (event.getIndex() != null)) {
        rows.add(event);
      }
      finished = true;
      notify();
    }

    public List<TableEvent> getRows() {
      return rows;
    }

    public boolean isFinished() {
      return finished;
    }
  }
}
