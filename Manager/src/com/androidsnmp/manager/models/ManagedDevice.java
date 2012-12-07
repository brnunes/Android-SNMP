/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.models;

import com.androidsnmp.manager.gui.PhonePanel;
import com.androidsnmp.manager.main.SNMPMessenger;
import java.util.Vector;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

/**
 *
 * @author brnunes
 */
public class ManagedDevice {
    private String ip;
    private String port = "32150";
    
    
    private boolean gpsStatus;
    private boolean networkStatus;
    private boolean bluetoothStatus;
    private boolean batteryStatus;
    private int batteryLevel;
    private PhonePanel phonePanel;
    private SNMPMessenger snmpMessenger;
    
    public ManagedDevice(String ip) {
        this.ip = ip;
        
        phonePanel = new PhonePanel(this);
        phonePanel.setIpLabel(ip);
        
        snmpMessenger = new SNMPMessenger(ip, port, this);
    }

    public String getIp() {
        return ip;
    }

    public boolean isGpsStatus() {
        return gpsStatus;
    }

    public boolean isNetworkStatus() {
        return networkStatus;
    }

    public boolean isBluetoothStatus() {
        return bluetoothStatus;
    }

    public boolean isBatteryStatus() {
        return batteryStatus;
    }

    public int getBatteryLevel() {
        return batteryLevel;
    }

    public PhonePanel getPhonePanel() {
        return phonePanel;
    }
    
    public void updateGPSStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,3,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setGpsLabelText(variableBinding.get(0).toValueString());
            }
        });
    }                                     

    public void updateNetworkStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,5,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setNetworkLabelText(variableBinding.get(0).toValueString());
            }
        });
    }                                         

    public void updateBluetoothStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,4,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setBluetoothLabelText(variableBinding.get(0).toValueString());
            }
        });
    }

    public void updateBatteryStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,1,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setBatteryStatusLabelText(variableBinding.get(0).toValueString());
            }
        });
    }

    public void updateBatteryLevel() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,2,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setBatteryLevelLabelText(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateModelName() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,1,1,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setModelValueLabelText(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateVersionName() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,1,2,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setVersionValueLabel(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateUpTime() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,1,3,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                phonePanel.setUpTimeValueLabelText(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateTableData() {
        OID[] columns = new OID[]{new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,1}), 
                                new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,2}),
                                new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,3}),
                                new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,4})};
        
        
        snmpMessenger.getTable(columns, new SNMPTableResponseListener() {
            boolean firstRow = true;

            public void onRowReceived(Object[] row) {
                if(firstRow) {
                    phonePanel.clearTable();
                    firstRow = false;
                }
                
                phonePanel.addTableRow(row);
            }

            public void onTableReceived() {
                throw new UnsupportedOperationException("Not supported yet.");
            }
        });
    }
    
    public static boolean isIpValid(String ip) {
        return ip.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    }
}
