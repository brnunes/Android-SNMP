/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.main;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Integer32;
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
    private String ip;
    private String port;
    
    private Snmp snmp;
    private ResponseListener listener;
    private CommandResponder trapPrinter;
    private CommunityTarget target;
    
    private PDU currentPDU;

    public SNMPMessenger(String ip, String port) {
        this.ip = ip;
        this.port = port;
        
        // setting up target
        target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(new UdpAddress(ip + "/" + port));
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version1);
        
        trapPrinter = new CommandResponder() {
            public synchronized void processPdu(CommandResponderEvent e) {
                PDU command = e.getPDU();
                if (command != null) {
                    System.out.println("trapPrinter: " + command.toString());
                    if(command.getRequestID().getValue() == currentPDU.getRequestID().getValue()) {
                        snmp.cancel(currentPDU, listener);
                    }
                }
            }
        };
        
        try {
            snmp = new Snmp(new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/" + port)));
            snmp.addCommandResponder(trapPrinter);
            snmp.listen();
        } catch (IOException e) {
            e.printStackTrace();
        }

        listener = new ResponseListener() {
            public void onResponse(ResponseEvent event) {
                // Always cancel async request when response has been received
                // otherwise a memory leak is created! Not canceling a request
                // immediately can be useful when sending a request to a broadcast
                // address.
                ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                PDU response = event.getResponse();
                PDU request = event.getRequest();
                if (response == null) {
                    System.out.println("listener: Request " + request + " timed out");
                } else {
                    System.out.println("listener: Received response " + response + " on request "
                            + request);
                }
            }
        };
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
         } catch (IOException e) {
         e.printStackTrace();
         }*/
    }

    public void sendGetRequest(OID oid) {
        // creating PDU
        currentPDU = new PDU();
        currentPDU.add(new VariableBinding(oid));
        currentPDU.setType(PDU.GET);

        try {
            snmp.send(currentPDU, target, null, listener);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
