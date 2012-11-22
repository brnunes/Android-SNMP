/**
 *
 * User: paulo
 * Date: 11/19/12
 * Time: 11:57 PM
 */

import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.Console;
import java.io.IOException;

public class GerenteMain {



    private Snmp snmp;


    ResponseListener listener = new ResponseListener() {
        public void onResponse(ResponseEvent event) {
            // Always cancel async request when response has been received
            // otherwise a memory leak is created! Not canceling a request
            // immediately can be useful when sending a request to a broadcast
            // address.
            ((Snmp)event.getSource()).cancel(event.getRequest(), this);
            PDU response = event.getResponse();
            PDU request = event.getRequest();
            if (response == null) {
                System.out.println("Request "+request+" timed out");
            }
            else {
                System.out.println("Received response "+response+" on request "+
                        request);
            }
        }
    };

    CommandResponder trapPrinter = new CommandResponder() {
        public synchronized void processPdu(CommandResponderEvent e) {
            PDU command = e.getPDU();
            if (command != null) {
                System.out.println(command.toString());
            }
        }
    };

    private void sendGetNextRequest(){
        // creating PDU
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID(new int[] {1,3,6,1,2,1,1,1})));
        pdu.add(new VariableBinding(new OID(new int[] {1,3,6,1,2,1,1,2})));
        pdu.setType(PDU.GETNEXT);

        // setting up target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(new UdpAddress("192.168.0.101/1610"));
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version1);

        try {
            snmp = new Snmp(new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/1610")));
            snmp.send(pdu, target, null, listener);
            snmp.addCommandResponder(trapPrinter);
            snmp.listen();

        }  catch (IOException e) {
            e.printStackTrace();
        }

    }



    public static void main(String[] args) {

        // Create window console
        MyWin mw = new MyWin();
        mw.addWindowListener ( new WindowAdapter() {
            public void windowClosing (WindowEvent e) {
                System.exit(0);
            }
        });

        GerenteMain gerenteMain = new GerenteMain();
        gerenteMain.sendGetNextRequest();

    }

}
