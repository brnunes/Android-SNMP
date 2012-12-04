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

    public SNMPMessenger(String ip, String port) {
        this.ip = ip;
        this.port = port;
        
        try {
            snmp = new Snmp(new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/" + port)));
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
                    System.out.println("Request " + request + " timed out");
                } else {
                    System.out.println("Received response " + response + " on request "
                            + request);
                }
            }
        };

        trapPrinter = new CommandResponder() {
            public synchronized void processPdu(CommandResponderEvent e) {
                PDU command = e.getPDU();
                if (command != null) {
                    System.out.println(command.toString());
                }
            }
        };
    }

    public void sendGetNextRequest() {
        // creating PDU
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
        }
    }
    
    public void sengGetRequest(OID oid) {
        // creating PDU
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(oid));
        pdu.setType(PDU.GET);

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
        }
    }
}
