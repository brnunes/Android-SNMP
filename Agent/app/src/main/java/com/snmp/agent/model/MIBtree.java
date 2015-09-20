package com.snmp.agent.model;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

import java.io.OptionalDataException;
import java.util.*;


public class MIBtree {
    public static final OID SYS_MODEL_NUMBER_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,1,1});
    public static final OID SYS_ANDROID_VERSION_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,1,2});
    public static final OID SYS_UPTIME_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,1,3});
    public static final OID SRVC_NUMBER_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,1});
    public static final OID SRVC_TABLE_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,2});
    public static final OID SRVC_ENTRY_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1});
    public static final OID SRVC_INDEX_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,1});
    public static final OID SRVC_DESCR_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,2});
    public static final OID SRVC_RUNNING_TIME_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,3});
    public static final OID SRVC_MEMORY_USED_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,2,2,1,4});
    public static final OID HW_BATTERY_STATUS_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,3,1});
    public static final OID HW_BATTERY_LEVEL_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,3,2});
    public static final OID HW_GPS_STATUS_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,3,3});
    public static final OID HW_BLUETOOTH_STATUS_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,3,4});
    public static final OID HW_NETWOK_STATUS_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,3,5});
    public static final OID HW_CAMERA_STATUS_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,3,6});
    public static final OID MNG_MANAGER_MESSAGE_OID = new OID(new int[] {1,3,6,1,4,1,12619,1,4,1});

    private static MIBtree uniqInstance;

    public static synchronized MIBtree getInstance() {
        if (uniqInstance == null) {
            uniqInstance = new MIBtree();
        }
        return uniqInstance;
    }
    private Node root;

    public MIBtree() {
        root = null;
    }

    private class Node {
        private VariableBinding data;
        private Node parent = null;
        private List<Node> children = null;

        @Override
        public boolean equals(Object o) {
            return super.equals(o);
        }
    }

    private class CompareNode implements Comparator<Node> {
        @Override
        public int compare(Node o1, Node o2) {
            return o1.data.getOid().compareTo(o2.data.getOid());
        }
    }

    public void addNode(VariableBinding data){
        synchronized (this) {
            OID oid = data.getOid();
            if(root == null){
                root = new Node();
                OID rootOID = new OID(new int[]{oid.get(0)});
                root.data = new VariableBinding(rootOID);
                addNode(root, data, 1);
            } else {
                addNode(root, data, 1);
            }
        }
    }

    private void addNode(Node node, VariableBinding data, int level){
        Node parent = null;
        OID oid = data.getOid();
        List<Node> listNode = node.children;
        if(listNode == null){
            listNode = new ArrayList<>();
            node.children = listNode;
        }

        //find node
        for(int i = 0; i < listNode.size(); i++){
            if(listNode.get(i).data.getOid().get(level) == oid.get(level)) parent = listNode.get(i);
        }

        if(level < (oid.size()-1)){

            if(parent != null) addNode(parent, data, level+1);
            else {
                Node aux = new Node();
                aux.parent = node;
                OID rootOID = (OID)node.data.getOid().clone();
                rootOID.append(oid.get(level)); //new OID(new int[]{oid.get(level)});
                aux.data = new VariableBinding(rootOID);
                listNode.add(aux);
                addNode(aux, data, level+1);
            }
        } else {
            if(parent == null) {
                parent = new Node();
                listNode.add(parent);
            }
            parent.parent = node;
            parent.children = null;
            OID rootOID = (OID)node.data.getOid().clone();
            rootOID.append(oid.get(level));
            parent.data = new VariableBinding(rootOID, data.getVariable());
        }

    }

    public void print(){
        print(root);
    }

    private void print(Node node){
        if(node != null) {
            System.out.println(node.data.toString());
            if(node.children != null) {
                for(Node n : node.children){
                    print(n);
                }
            }
        }
    }

    public VariableBinding get(OID oid) {
        synchronized (this) {
            VariableBinding vb;
            Node aux = root;
            for(int i = 1; i < oid.size() && aux != null; i++){
                aux = findNode(aux.children, oid.get(i), i);

            }
            vb = new VariableBinding(oid);
            vb.setVariable(aux.data.getVariable());
            return vb;
        }
    }

    public VariableBinding getNext(OID oid){
        synchronized (this) {
            Node aux = root;
            for(int i = 1; i < oid.size() && aux != null; i++){
                aux = findNode(aux.children, oid.get(i),i);
            }
            aux = getNextNode(oid, aux);
            if(aux == null) return new VariableBinding(oid);
            return aux.data;
        }
    }

    private Node getNextNode(OID oid, Node node) {
        if(node == null) return null;
        if(node.children != null && node.children.size() > 0) {
            while(node.children != null && node.children.size() > 0){
                node = node.children.get(0);
            }

            return node;
        } else {
            node = node.parent;

            while(node != null && hasNext(oid, node.children)==null){
                System.out .println(node.data.getOid().toString());
                node = node.parent;
            }

            if(node == null) {
                System.out .println("NULL CRRR");return null;
            }

            node = hasNext(oid, node.children);

            while(node != null && node.children != null && node.children.size() > 0){
                node = node.children.get(0);
            }

            return node;
        }

    }

    private Node hasNext(OID oid, List<Node> nodes){
        Collections.sort(nodes, new CompareNode());
        for(Node n : nodes){
            OID nodeOID = n.data.getOid();
            int oidIndex = nodeOID.size()-1;
            int idValue = nodeOID.get(oidIndex);
            if(idValue > oid.get(oidIndex)) return n;

        }
        return null;
    }

    public void set(VariableBinding vb) {
        /*
        OID oid = vb.getOid();
        Node aux = root;
        for(int i = 1; i < oid.size(); i++){
            aux = findNode(aux.children, oid.get(i), i);
        }
        aux.data.setVariable(vb.getVariable());
        */
        addNode(vb);
    }

    private Node findNode(List<Node> list, int oid, int i){
        for(Node n : list){
            if(n.data.getOid().get(i) == oid) return n;
        }
        return null;
    }

   public void clearNode(OID oid){
       synchronized (this) {
           Node aux = root;
           for(int i = 1; i < oid.size() && aux != null; i++){
               aux = findNode(aux.children, oid.get(i), i);
           }
           aux.children.clear();
           aux.children = null;
       }
   }

   public static synchronized void setNewMIB(MIBtree mib) {
       uniqInstance = mib;
   }

}
