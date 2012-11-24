package com.snmp.agent.model;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

import java.util.ArrayList;
import java.util.List;


public class MIBtree {
    private Node root;

    public MIBtree() {
        root = null;
    }

    private class Node {
        private VariableBinding data;
        private Node parent;
        private List<Node> children;
    }

    private void addNode(VariableBinding data){
        OID oid = data.getOid();
        if(root == null){
            root = new Node();
            OID rootOID = new OID(new int[]{oid.get(0)});
            root.data = new VariableBinding(rootOID, null);
        }

    }
}
