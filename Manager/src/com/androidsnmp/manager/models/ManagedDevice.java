/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.models;

import com.androidsnmp.manager.gui.PhonePanel;

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
    
    public ManagedDevice(String ip) {
        phonePanel = new PhonePanel(this);
        this.ip = ip;
        phonePanel.setIpLabel(ip);
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
        System.out.println(ip + ": gpsLabelMouseClicked");
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
