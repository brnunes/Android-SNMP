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
        this.ip = ip;
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
}
