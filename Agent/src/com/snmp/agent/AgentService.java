package com.snmp.agent;

import android.app.Service;
import android.content.Intent;
import android.os.*;
import android.util.Log;
import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.MessageProcessingModel;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.ArrayList;

public class AgentService extends Service implements CommandResponder {

    /** Keeps track of all current registered clients. */
    ArrayList<Messenger> mClients = new ArrayList<Messenger>();
    /** Holds last value set by a client. */
    int mValue = 0;

    static final int MSG_REGISTER_CLIENT = 1;
    static final int MSG_UNREGISTER_CLIENT = 2;
    static final int MSG_SET_VALUE = 3;
    static final int MSG_SNMP_REQUEST_RECEIVED = 4;
    public static final int MSN_SEND_DANGER_TRAP = 5;

    public static String lastRequestReceived = "";

    private Snmp snmp;

    /**
     * Handler of incoming messages from clients.
     */
    class IncomingHandler extends Handler {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MSG_REGISTER_CLIENT:
                    mClients.add(msg.replyTo);
                    break;
                case MSG_UNREGISTER_CLIENT:
                    mClients.remove(msg.replyTo);
                    break;
                case MSG_SET_VALUE:
                    mValue = msg.arg1;
                    sendMessageToClients(MSG_SET_VALUE);
                    break;
                case MSN_SEND_DANGER_TRAP:
                    new SendTrap().execute();
                    break;
                default:
                    super.handleMessage(msg);
            }
        }
    }

    private void sendMessageToClients(int msgCode) {
        for (int i=mClients.size()-1; i>=0; i--) {
            try {
                mClients.get(i).send(Message.obtain(null,
                        msgCode, 0, 0));
            } catch (RemoteException e) {
                // The client is dead.  Remove it from the list;
                // we are going through the list from back to front
                // so this is safe to do inside the loop.
                mClients.remove(i);
            }
        }
    }

    /**
     * Target we publish for clients to send messages to IncomingHandler.
     */
    final Messenger mMessenger = new Messenger(new IncomingHandler());

    @Override
    public void onCreate() {
        new AgentListener().start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i("LocalService", "Received start id " + startId + ": " + intent);
        // We want this service to continue running until it is explicitly
        // stopped, so return sticky.
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mMessenger.getBinder();
    }

    @Override
    public void onDestroy() {

    }

    private class SendTrap extends AsyncTask<Void, Void, Void> {
        protected Void doInBackground(Void... params) {
            PDUv1 pdu = new PDUv1();
            pdu.setType(PDU.V1TRAP);
            pdu.setGenericTrap(PDUv1.COLDSTART);
            pdu.add(new VariableBinding(new OID(new int[]{1, 3, 6, 1, 2, 1, 1, 2})));

            // Specify receiver
            Address targetAddress = new UdpAddress("192.168.0.103/1610");
            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString("public"));
            target.setVersion(SnmpConstants.version1);
            target.setAddress(targetAddress);
            target.setRetries(2);
            target.setTimeout(1500);


            try {
                snmp.trap(pdu, target);
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private class AgentListener extends Thread {
        public void run() {
            try {

                initSnmp();

                snmp.listen();

            }  catch (IOException e) {
                e.printStackTrace();
            }
        }

        private void initSnmp(){
            try {
                TransportMapping transport = null;
                transport = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/1610"));

                snmp = new Snmp(transport);


                snmp.addCommandResponder(AgentService.this);

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public synchronized void processPdu(CommandResponderEvent commandResponderEvent) {
        PDU command = commandResponderEvent.getPDU();

        //lastRequestReceiverTextView.setText(command.toString() + " " + commandResponderEvent.getPeerAddress().toString());
        if (command != null) {
            System.out.println(command.toString() + " " + commandResponderEvent.getPeerAddress().toString());
            lastRequestReceived = command.toString() + " " + commandResponderEvent.getPeerAddress().toString();
            sendMessageToClients(MSG_SNMP_REQUEST_RECEIVED);
        }
    }
}
