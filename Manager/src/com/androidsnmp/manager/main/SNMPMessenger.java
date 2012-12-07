/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.main;

import com.androidsnmp.manager.models.ManagedDevice;
import com.androidsnmp.manager.models.SNMPResponseListener;
import com.androidsnmp.manager.models.SNMPTableResponseListener;
import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TableEvent;
import org.snmp4j.util.TableListener;
import org.snmp4j.util.TableUtils;

/**
 *
 * @author brnunes
 */
public class SNMPMessenger {
    private static final String community = "public";
    private static final int snmpVersion = SnmpConstants.version1;
    
    private String ip;
    private String port;
    private CommunityTarget comtarget;
    
    private ManagedDevice device;

    public SNMPMessenger(String ip, String port, ManagedDevice device) {
        this.ip = ip;
        this.port = port;
        this.device = device;

        // Create Target Address object
        comtarget = new CommunityTarget();
        comtarget.setCommunity(new OctetString(community));
        comtarget.setVersion(snmpVersion);
        comtarget.setAddress(new UdpAddress(ip + "/" + port));
        comtarget.setRetries(2);
        comtarget.setTimeout(1000);
    }

    public void sendGetNextRequest() {
        /*// creating PDU
         PDU pdu = new PDU();
         pdu.add(new VariableBinding(new OID(new int[]{1, 3, 6, 1, 2, 1, 1, 1})));
         pdu.add(new VariableBinding(new OID(new int[]{1, 3, 6, 1, 2, 1, 1, 2})));
         pdu.setType(PDU.GETNEXT);

         // setting up target
         CommunityTarget target = new CommunityTarget();
         target.setCommunity(new OctetString("public"));
         target.setAddress(new UdpAddress(ip + "/" + port));
         target.setRetries(2);
         target.setTimeout(1500);
         target.setVersion(SnmpConstants.version1);

         try {
         snmp.send(pdu, target, null, listener);
         snmp.addCommandResponder(trapPrinter);
         snmp.listen();
         } catch (IOException e) {
         e.printStackTrace();
         }*/
    }
    
    public void getTable(OID[] columns, final SNMPTableResponseListener responseListener) {
        try {
            // Create Snmp object for sending data to Agent
            Snmp snmp = new Snmp(new DefaultUdpTransportMapping());
            snmp.listen();

            TableUtils tableUtils = new TableUtils(snmp, new DefaultPDUFactory(PDU.GETBULK));
            
            TableListener listener = new TableListener() {
                private boolean finished = false;

                public boolean next(TableEvent event) {
                    System.out.println("OID: " + event.getIndex());
                    System.out.println("Columns:");
                    
                    int numColumns = event.getColumns().length;
                    
                    String[] row = new String[numColumns];
                    
                    for(int i = 0; i < numColumns; i++) {
                        System.out.println(i + ": " + event.getColumns()[i]);
                        row[i] = event.getColumns()[i].toValueString();
                        System.out.println("Row: " + row[i]);
                    }
                    
                    responseListener.onRowReceived(row);
                    
                    return true;
                }

                public void finished(TableEvent event) {
                    finished = true;
                }

                public boolean isFinished() {
                    return finished;
                }
            };
            
            System.out.println("Starting to get table ...");
            
            tableUtils.getTable(comtarget, columns, listener, null, null, null);
            
        } catch (java.io.IOException e) {
            e.printStackTrace();
        }
    }

    public void sendGetRequest(OID oid, final SNMPResponseListener responseListener) {
        try {
            // Create the PDU object
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(oid)));
            pdu.setType(PDU.GET);

            // Create Snmp object for sending data to Agent
            Snmp snmp = new Snmp(new DefaultUdpTransportMapping());
            snmp.listen();

            ResponseListener listener = new ResponseListener() {
                public void onResponse(ResponseEvent event) {
                    // Always cancel async request when response has been received
                    // otherwise a memory leak is created! Not canceling a request
                    // immediately can be useful when sending a request to a broadcast
                    // address.
                    ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                    PDU response = event.getResponse();
                    PDU request = event.getRequest();
                    if (response != null) {
                        System.out.println("Got Response from Agent");
                        int errorStatus = response.getErrorStatus();
                        int errorIndex = response.getErrorIndex();
                        String errorStatusText = response.getErrorStatusText();

                        if (errorStatus == PDU.noError) {
                            System.out.println("Snmp Get Response = " + response.getVariableBindings());
                            responseListener.onSNMPResponseReceived(response.getVariableBindings());
                        } else {
                            System.out.println("Error: Request Failed");
                            System.out.println("Error Status = " + errorStatus);
                            System.out.println("Error Index = " + errorIndex);
                            System.out.println("Error Status Text = " + errorStatusText);
                        }
                    } else {
                        System.out.println("Error: Agent Timeout... ");
                    }
                }
            };
            
            System.out.println("Sending Request to Agent...");
            
            snmp.send(pdu, comtarget, "user_handle_object", listener);
            
        } catch (java.io.IOException e) {
            e.printStackTrace();
        }
    }
}
