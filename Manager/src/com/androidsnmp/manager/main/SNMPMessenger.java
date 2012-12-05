/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.main;

import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

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

    public SNMPMessenger(String ip, String port) {
        this.ip = ip;
        this.port = port;

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

    public void sendGetRequest(OID oid) {
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
