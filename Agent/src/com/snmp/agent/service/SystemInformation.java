package com.snmp.agent.service;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.os.SystemClock;
import com.snmp.agent.model.MIBtree;
import org.snmp4j.smi.*;

import java.util.List;

/**
 * User: paulo
 * Date: 11/28/12
 * Time: 8:48 PM
 */
public class SystemInformation {

    private Context context;
    private MIBtree MIB_MAP;

    public SystemInformation(Context context){
        this.context = context;

        MIB_MAP = MIBtree.getInstance();
    }

    public void updateSystemInformation(){
        updateDeviceModel();
        updateAndroidVersion();
        updateUptime();
        updateRunningServices();
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

        for(ActivityManager.RunningServiceInfo serviceInfo : runningServices){
            oid = (OID)MIBtree.SRVC_INDEX_OID.clone();
            vb = new VariableBinding(oid.append(serviceInfo.pid),new Integer32(serviceInfo.pid));
            MIB_MAP.set(vb);
            oid = (OID)MIBtree.SRVC_DESCR_OID.clone();
            vb = new VariableBinding(oid.append(serviceInfo.pid),new OctetString(serviceInfo.process));
            MIB_MAP.set(vb);

            Debug.MemoryInfo[] memoryInfos = activityManager.getProcessMemoryInfo(new int[]{serviceInfo.pid});
            oid = (OID)MIBtree.SRVC_MEMORY_USED_OID.clone();
            vb = new VariableBinding(oid.append(serviceInfo.pid),new Integer32(memoryInfos[0].getTotalPss()));
            MIB_MAP.set(vb);

            oid = (OID)MIBtree.SRVC_RUNNING_TIME_OID.clone();
            Long time = System.currentTimeMillis() - serviceInfo.activeSince;
            vb = new VariableBinding(oid.append(serviceInfo.pid),new TimeTicks(time.intValue()));
            MIB_MAP.set(vb);

        }

    }
}
