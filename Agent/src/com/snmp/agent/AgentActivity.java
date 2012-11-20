package com.snmp.agent;

import android.app.Activity;
import android.os.Bundle;

import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.MessageProcessingModel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class AgentActivity extends Activity implements CommandResponder {
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        new AgentListener().start();
    }

    private class AgentListener extends Thread {

        public void run() {
            try {
                TransportMapping transport = null;
                transport = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/1610"));

                Snmp snmp = new Snmp(transport);
                //if (SnmpConstants.version3) {
                    byte[] localEngineID =
                            ((MPv3)snmp.getMessageProcessingModel(MessageProcessingModel.MPv3)).createLocalEngineID();
                    USM usm = new USM(SecurityProtocols.getInstance(),
                            new OctetString(localEngineID), 0);
                    SecurityModels.getInstance().addSecurityModel(usm);
                    snmp.setLocalEngine(localEngineID, 0, 0);
                    // Add the configured user to the USM

                //}
                snmp.addCommandResponder(AgentActivity.this);
                snmp.listen();

            }  catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    @Override
    public synchronized void processPdu(CommandResponderEvent commandResponderEvent) {
        System.out.println("Chegou algo aqui!!! Dale Dale");
        PDU command = commandResponderEvent.getPDU();
        System.out.println(command.toString());
        if (command != null) {

        }
    }
}
