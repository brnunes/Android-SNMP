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
        
        snmpMessenger = new SNMPMessenger(ip, "1610");
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
    
    public void gpsClicked() {
        snmpMessenger.sengGetRequest(new OID(new int[] {1,3,6,1,4,1,12619,1,3,2}));
    }                                     

    public void networkClicked() {                                          
        System.out.println(ip + ": networkLabelMouseClicked");
    }                                         

    public void bluetoothClicked() {                                            
        System.out.println(ip + ": bluetoothLabelMouseClicked");
    }                                           

    public void batteryStatusClicked() {                                                
        System.out.println(ip + ": batteryStatusLabelMouseClicked");
    }                                               

    public void batteryLevelClicked() {                                               
        System.out.println(ip + ": batteryLevelLabelMouseClicked");
    }
    
    public static boolean isIpValid(String ip) {
        return ip.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    }
}
