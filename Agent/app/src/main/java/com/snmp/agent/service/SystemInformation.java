package com.snmp.agent.service;

import android.app.ActivityManager;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.location.LocationManager;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Debug;
import android.os.SystemClock;
import com.snmp.agent.model.MIBtree;
import org.snmp4j.smi.*;

import java.util.List;

public class SystemInformation {

    private Context context;
    private MIBtree MIB_MAP;

    public SystemInformation(Context context){
        this.context = context;

        MIB_MAP = new MIBtree();
    }

    public void updateSystemInformation(){
        MIB_MAP = new MIBtree();

        updateDeviceModel();
        updateAndroidVersion();
        updateUptime();
        updateRunningServices();
        updateBatteryStatus();
        updateBatteryLevel();
        updateGPSStatus();
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) updateBluetoothStatus();
        updateNetworkStatus();

        MIBtree.setNewMIB(MIB_MAP);
    }

    private void updateDeviceModel() {
        String model = Build.MANUFACTURER + " " + Build.MODEL;
        OID oid = (OID)MIBtree.SYS_MODEL_NUMBER_OID.clone();
        VariableBinding vb = new VariableBinding(oid.append(0),new OctetString(model));
        MIB_MAP.set(vb);
    }

    private void updateAndroidVersion() {
        String version = Build.VERSION.RELEASE;
        OID oid = (OID)MIBtree.SYS_ANDROID_VERSION_OID.clone();
        VariableBinding vb = new VariableBinding(oid.append(0),new OctetString(version));
        MIB_MAP.set(vb);
    }

    private void updateUptime() {
        Long time = SystemClock.uptimeMillis();
        OID oid = (OID)MIBtree.SYS_UPTIME_OID.clone();
        VariableBinding vb = new VariableBinding(oid.append(0),new TimeTicks(time.intValue()));
        MIB_MAP.set(vb);
    }

    private void updateRunningServices(){
        VariableBinding vb;
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningServiceInfo> runningServices =  activityManager.getRunningServices(100);

        OID oid = (OID)MIBtree.SRVC_NUMBER_OID.clone();
        vb = new VariableBinding(oid.append(0),new Integer32(runningServices.size()));
        MIB_MAP.set(vb);
        int i = 0;
        for(ActivityManager.RunningServiceInfo serviceInfo : runningServices){
            i++;
            System.out.println(serviceInfo.pid);
            oid = (OID)MIBtree.SRVC_INDEX_OID.clone();
            vb = new VariableBinding(oid.append(i),new Integer32(serviceInfo.pid));
            MIB_MAP.set(vb);
            oid = (OID)MIBtree.SRVC_DESCR_OID.clone();
            vb = new VariableBinding(oid.append(i),new OctetString(serviceInfo.process));
            MIB_MAP.set(vb);

            Debug.MemoryInfo[] memoryInfos = activityManager.getProcessMemoryInfo(new int[]{serviceInfo.pid});
            oid = (OID)MIBtree.SRVC_MEMORY_USED_OID.clone();
            vb = new VariableBinding(oid.append(i),new Integer32(memoryInfos[0].getTotalPss()));
            MIB_MAP.set(vb);

            oid = (OID)MIBtree.SRVC_RUNNING_TIME_OID.clone();
            Long time = serviceInfo.activeSince;
            vb = new VariableBinding(oid.append(i),new TimeTicks(time.intValue()));
            MIB_MAP.set(vb);
        }
    }

    private void updateBatteryStatus(){
        VariableBinding vb;

        OID oid = (OID)MIBtree.HW_BATTERY_STATUS_OID.clone();

        IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = context.registerReceiver(null, ifilter);

        // Are we charging / charged?
        int status = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
        boolean isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                status == BatteryManager.BATTERY_STATUS_FULL;

        vb = new VariableBinding(oid.append(0),new Integer32(isCharging ? 1 : 0));

        MIB_MAP.set(vb);
    }

    private void updateBatteryLevel(){
        VariableBinding vb;

        IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = context.registerReceiver(null, ifilter);

        int level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);

        float batteryPct = level / (float)scale;

        OID oid = (OID)MIBtree.HW_BATTERY_LEVEL_OID.clone();
        vb = new VariableBinding(oid.append(0),new Integer32(level));

        MIB_MAP.set(vb);
    }

    private void updateGPSStatus(){
        VariableBinding vb;

        LocationManager manager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        boolean statusOfGPS = manager.isProviderEnabled(LocationManager.GPS_PROVIDER);

        OID oid = (OID)MIBtree.HW_GPS_STATUS_OID.clone();
        vb = new VariableBinding(oid.append(0),new Integer32(statusOfGPS ? 1 : 0));

        MIB_MAP.set(vb);
    }

    private void updateBluetoothStatus(){
        VariableBinding vb;

        BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        boolean isOn = bluetoothAdapter.getState() == BluetoothAdapter.STATE_ON
                || bluetoothAdapter.getState() == BluetoothAdapter.STATE_TURNING_ON;

        OID oid = (OID)MIBtree.HW_BLUETOOTH_STATUS_OID.clone();
        vb = new VariableBinding(oid.append(0),new Integer32(isOn ? 1 : 0));

        MIB_MAP.set(vb);
    }

    private void updateNetworkStatus(){
        VariableBinding vb;

        WifiManager wifiManager = (WifiManager) context
                .getSystemService(Context.WIFI_SERVICE);

        boolean isOn = wifiManager.getWifiState() == WifiManager.WIFI_STATE_ENABLED
                || wifiManager.getWifiState() == WifiManager.WIFI_STATE_ENABLING;

        OID oid = (OID)MIBtree.HW_NETWOK_STATUS_OID.clone();
        vb = new VariableBinding(oid.append(0),new Integer32(isOn ? 1 : 0));

        MIB_MAP.set(vb);
    }
}
