package com.androidsnmp.manager.main;

import com.androidsnmp.manager.gui.ManagerFrame;
import com.androidsnmp.manager.models.ManagedDevice;
import javax.swing.DefaultListModel;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public class AndroidSNMPManager {
    private DefaultListModel<ManagedDevice> sampleModel;
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
                managerFrame.setLocationRelativeTo(null);
                managerFrame.setVisible(true);
            }
        });
    }
    
    public AndroidSNMPManager() {
        sampleModel = new DefaultListModel<ManagedDevice>();
    }

    public DefaultListModel<ManagedDevice> getSampleModel() {
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
        AndroidSNMPManager.managerFrame.removePhonePanel(sampleModel.get(index).getPhonePanel());
        sampleModel.remove(index);
    }
    
    public String getLocalNetworkBroadcastAddress() throws SocketException {
    	final Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
    	while (interfaces.hasMoreElements()) {
    		    final NetworkInterface cur = interfaces.nextElement( );

				if (cur.isLoopback()) {
				    continue;
				}

    		    System.out.println("interface " + cur.getName());

    		    for (final InterfaceAddress addr : cur.getInterfaceAddresses()) {
    		        final InetAddress inet_addr = addr.getAddress( );

    		        if (!(inet_addr instanceof Inet4Address)) {
    		            continue;
    		        }

    		        System.out.println("  address: " + inet_addr.getHostAddress() +
    		            "/" + addr.getNetworkPrefixLength());

    		        String broadcastAddress = addr.getBroadcast().getHostAddress(); 
    		        System.out.println("  broadcast address: " + broadcastAddress);
    		        
    		        return broadcastAddress;
    		    }
    		}
    	
    	return null;
    }
    
    public ManagedDevice getManagedDevice(int index) {
        return sampleModel.get(index);
    }
    
    public boolean hasDevice(String deviceIp) {
        for(int i = 0; i < sampleModel.size(); i++) {
            if(sampleModel.get(i).getIp().equals(deviceIp)) {
                return true;
            }
        }
        
        return false;
    }
}
