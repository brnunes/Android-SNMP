/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.androidsnmp.manager.gui;

import com.androidsnmp.manager.models.ManagedDevice;
import java.awt.Color;
import java.awt.Component;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

/**
 *
 * @author brnunes
 */
public class ManagedDeviceCellRenderer extends JLabel implements ListCellRenderer {
    
    public ManagedDeviceCellRenderer() {
        setOpaque(true);
    }

    public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        ManagedDevice device = (ManagedDevice) value;
        setText(device.getIp());
        if(isSelected) {
            setBackground(Color.LIGHT_GRAY);
        }
        else {
            setBackground(null);
        }
        return this;
    }
    
}
