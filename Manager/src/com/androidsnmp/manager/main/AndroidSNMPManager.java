package com.androidsnmp.manager.main;

import com.androidsnmp.manager.gui.ManagerFrame;
import com.androidsnmp.manager.models.ManagedDevice;
import javax.swing.DefaultListModel;

public class AndroidSNMPManager {
    private DefaultListModel sampleModel;
    
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
        
        final AndroidSNMPManager main = new AndroidSNMPManager();
        
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                ManagerFrame managerFrame = new ManagerFrame(main);
                managerFrame.setLocation(100,100);
                managerFrame.setVisible(true);
            }
        });

        GerenteMain gerenteMain = new GerenteMain();
        gerenteMain.sendGetNextRequest();
    }
    
    public AndroidSNMPManager() {
        sampleModel = new DefaultListModel();
        sampleModel.add(0, new ManagedDevice("ip!"));
    }

    public DefaultListModel getSampleModel() {
        return sampleModel;
    }
    
    public void addManagedDevice(ManagedDevice device) {
        sampleModel.add(sampleModel.size(), device);
    }
    
    public void removeManagedDevice(int index) {
        sampleModel.remove(index);
    }
}
