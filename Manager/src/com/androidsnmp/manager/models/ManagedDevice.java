/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.models;

import com.androidsnmp.manager.gui.PhonePanel;
import com.androidsnmp.manager.main.SNMPMessenger;
import org.snmp4j.smi.OID;

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
        
        snmpMessenger = new SNMPMessenger(ip, port);
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
        snmpMessenger.sendGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,2,0}));
    }                                     

    public void updateNetworkStatus() {                                          
        System.out.println(ip + ": networkLabelMouseClicked");
    }                                         

    public void updateBluetoothStatus() {
        System.out.println(ip + ": bluetoothLabelMouseClicked");
    }

    public void updateBatteryStatus() {
        System.out.println(ip + ": batteryStatusLabelMouseClicked");
    }

    public void updateBatteryLevel() {
        System.out.println(ip + ": batteryLevelLabelMouseClicked");
    }
    
    public void updateModelName() {
        
    }
    
    public void updateVersionName() {
        
    }
    
    public void updateUpTime() {
        
    }
    
    public void updateTableData() {
        
    }
    
    public static boolean isIpValid(String ip) {
        return ip.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    }
}
