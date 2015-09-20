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
    public static String port = "32150";
    
    
    private String gpsStatus;
    private String networkStatus;
    private String bluetoothStatus;
    private String batteryStatus;
    private String batteryLevel;
    private String modelName;
    private String versionName;
    private String upTime;
    
    
    
    private PhonePanel phonePanel;
    private SNMPMessenger snmpMessenger;
    
    public ManagedDevice(String ip) {
        this.ip = ip;
        
        phonePanel = new PhonePanel(this);
        phonePanel.setIpLabel(ip);
        
        snmpMessenger = new SNMPMessenger(ip, port);
    }

    public String getIp() {
        return ip;
    }

    public PhonePanel getPhonePanel() {
        return phonePanel;
    }

    public void setGpsStatus(String gpsStatus) {
        this.gpsStatus = gpsStatus;
        phonePanel.setGpsLabelText(gpsStatus);
    }

    public void setNetworkStatus(String networkStatus) {
        this.networkStatus = networkStatus;
        phonePanel.setNetworkLabelText(networkStatus);
    }

    public void setBluetoothStatus(String bluetoothStatus) {
        this.bluetoothStatus = bluetoothStatus;
        phonePanel.setBluetoothLabelText(bluetoothStatus);
    }

    public void setBatteryStatus(String batteryStatus) {
        this.batteryStatus = batteryStatus;
         phonePanel.setBatteryStatusLabelText(batteryStatus);
    }

    public void setBatteryLevel(String batteryLevel) {
        this.batteryLevel = batteryLevel;
        phonePanel.setBatteryLevelLabelText(batteryLevel);
    }

    public void setModelName(String modelName) {
        this.modelName = modelName;
        phonePanel.setModelValueLabelText(modelName);
    }

    public void setVersionName(String versionName) {
        this.versionName = versionName;
        phonePanel.setVersionValueLabel(versionName);
    }

    public void setUpTime(String upTime) {
        this.upTime = upTime;
        phonePanel.setUpTimeValueLabelText(upTime);
    }
    
    public void updateGPSStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,3,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setGpsStatus(variableBinding.get(0).toValueString().equalsIgnoreCase("1")? "ON" : "OFF");
            }
        });
    }                                     

    public void updateNetworkStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,5,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setNetworkStatus(variableBinding.get(0).toValueString().equalsIgnoreCase("1")? "ON" : "OFF");
            }
        });
    }                                         

    public void updateBluetoothStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,4,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setBluetoothStatus(variableBinding.get(0).toValueString().equalsIgnoreCase("1")? "ON" : "OFF");
            }
        });
    }

    public void updateBatteryStatus() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,1,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
               setBatteryStatus(variableBinding.get(0).toValueString().equalsIgnoreCase("1")? "Charging" : "Discharging");
            }
        });
    }

    public void updateBatteryLevel() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,2,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setBatteryLevel(variableBinding.get(0).toValueString() + "%");
            }
        });
    }
    
    public void updateModelName() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,1,1,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setModelName(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateVersionName() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,1,2,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setVersionName(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateUpTime() {
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,1,3,0}), new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                setUpTime(variableBinding.get(0).toValueString());
            }
        });
    }
    
    public void updateEverything() {
    	updateGPSStatus();
    	updateNetworkStatus();
    	updateBluetoothStatus();
    	updateBatteryStatus();
    	updateBatteryLevel();
    	
    	updateModelName();
    	updateVersionName();
    	updateUpTime();
    	
    	updateTableData();
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
    
    public void sendMessage(String message) {
        snmpMessenger.sendSetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,4,1,0}), message, new SNMPResponseListener() {

            public void onSNMPResponseReceived(Vector<? extends VariableBinding> variableBinding) {
                System.out.println("-> " + variableBinding);
            }
        });
    }
    
    public static boolean isIpValid(String ip) {
        return ip.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    }
}
