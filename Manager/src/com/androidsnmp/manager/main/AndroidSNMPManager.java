package com.androidsnmp.manager.main;

import com.androidsnmp.manager.gui.ManagerFrame;
import com.androidsnmp.manager.models.ManagedDevice;
import javax.swing.DefaultListModel;

public class AndroidSNMPManager {
    private DefaultListModel sampleModel;
    private static ManagerFrame managerFrame;
    
    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ManagerFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ManagerFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ManagerFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ManagerFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        final AndroidSNMPManager androidSNMPManager = new AndroidSNMPManager();
        
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                managerFrame = new ManagerFrame(androidSNMPManager);
                managerFrame.setLocation(100,100);
                managerFrame.setVisible(true);
                
                androidSNMPManager.addManagedDevice(new ManagedDevice("192.168.0.10"));
            }
        });
        

        GerenteMain gerenteMain = new GerenteMain();
        gerenteMain.sendGetNextRequest();
    }
    
    public AndroidSNMPManager() {
        sampleModel = new DefaultListModel();
    }

    public DefaultListModel getSampleModel() {
        return sampleModel;
    }
    
    public void addManagedDevice(ManagedDevice device) {
        sampleModel.add(sampleModel.size(), device);
        AndroidSNMPManager.managerFrame.addPhonePanel(device, device.getIp());
    }
    
    public void addManagedDevice(ManagedDevice device, int index) {
        sampleModel.add(index, device);
        AndroidSNMPManager.managerFrame.addPhonePanel(device, device.getIp());
    }
    
    public void removeManagedDevice(int index) {
        AndroidSNMPManager.managerFrame.removePhonePanel(((ManagedDevice) sampleModel.get(index)).getPhonePanel());
        sampleModel.remove(index);
    }
    
    public ManagedDevice getManagedDevice(int index) {
        return (ManagedDevice) sampleModel.get(index);
    }
    
    public boolean hasDevice(String deviceIp) {
        for(int i = 0; i < sampleModel.size(); i++) {
            if(((ManagedDevice) sampleModel.get(i)).getIp().equals(deviceIp)) {
                return true;
            }
        }
        
        return false;
    }
}
