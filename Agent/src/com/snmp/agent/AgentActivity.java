package com.snmp.agent;

import android.app.Activity;
import android.os.Bundle;

import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;
import com.snmp.actionbarcompat.ActionBarActivity;
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

public class AgentActivity extends ActionBarActivity implements CommandResponder {
    /** Called when the activity is first created. */
    private boolean mAlternateTitle = false;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        findViewById(R.id.toggle_title).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (mAlternateTitle) {
                    setTitle(R.string.app_name);
                } else {
                    setTitle(R.string.alternate_title);
                }
                mAlternateTitle = !mAlternateTitle;
            }
        });

        new AgentListener().start();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater menuInflater = getMenuInflater();
        menuInflater.inflate(R.menu.main, menu);

        // Calling super after populating the menu is necessary here to ensure that the
        // action bar helpers have a chance to handle this event.
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                Toast.makeText(this, "Tapped home", Toast.LENGTH_SHORT).show();
                break;

            case R.id.menu_refresh:
                Toast.makeText(this, "Fake refreshing...", Toast.LENGTH_SHORT).show();
                getActionBarHelper().setRefreshActionItemState(true);
                getWindow().getDecorView().postDelayed(
                        new Runnable() {
                            @Override
                            public void run() {
                                getActionBarHelper().setRefreshActionItemState(false);
                            }
                        }, 1000);
                break;

            case R.id.menu_search:
                Toast.makeText(this, "Tapped search", Toast.LENGTH_SHORT).show();
                break;

            case R.id.menu_share:
                Toast.makeText(this, "Tapped share", Toast.LENGTH_SHORT).show();
                break;
        }
        return super.onOptionsItemSelected(item);
    }


    private class AgentListener extends Thread {

        private Snmp snmp;

        private void sendTrap(){
            PDUv1 pdu = new PDUv1();
            pdu.setType(PDU.V1TRAP);
            pdu.setGenericTrap(PDUv1.COLDSTART);

            // Specify receiver
            Address targetAddress = new UdpAddress("192.168.0.103/1610");
            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString("public"));
            target.setVersion(SnmpConstants.version1);
            target.setAddress(targetAddress);

            try {
                snmp.trap(pdu, target);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void run() {
            try {
                TransportMapping transport = null;
                transport = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/1610"));

                snmp = new Snmp(transport);
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
