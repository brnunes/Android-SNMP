package com.snmp.agent.model;

import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

import java.io.OptionalDataException;
import java.util.*;


public class MIBtree {

    private static MIBtree uniqInstance;

    public static synchronized MIBtree getInstance() {
        if (uniqInstance == null) {
            uniqInstance = new MIBtree();
        }
        return uniqInstance;
    }
    private Node root;

    private MIBtree() {
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

    private void addNode(Node node, VariableBinding data, int level){
        Node parent = null;
        OID oid = data.getOid();
        List<Node> listNode = node.children;
        if(listNode == null){
            listNode = new ArrayList<Node>();
            node.children = listNode;
        }

        if(level < oid.size()){
            //find node
            for(int i = 0; i < listNode.size(); i++){
                if(listNode.get(i).data.getOid().get(level) == oid.get(level)) parent = listNode.get(i);
            }
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
            Node aux = new Node();
            aux.parent = node;
            aux.children = null;
            OID rootOID = (OID)node.data.getOid().clone();
            rootOID.append(listNode.size()); //new OID(new int[]{oid.get(level)});
            aux.data = new VariableBinding(rootOID, data.getVariable());
            listNode.add(aux);
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
        VariableBinding vb;
        Node aux = root;
        for(int i = 1; i < oid.size() && aux != null; i++){
            aux = findNode(aux.children, oid.get(i), i);

        }
        vb = new VariableBinding(oid);
        vb.setVariable(aux.data.getVariable());
        return vb;
    }

    public VariableBinding getNext(OID oid){
        Node aux = root;
        for(int i = 1; i < oid.size() && aux != null; i++){
            aux = findNode(aux.children, oid.get(i),i);
        }
        aux = getNextNode(oid, aux);
        if(aux == null) return new VariableBinding(oid);
        return aux.data;
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
            if(node == null) {System.out .println("NULL CRRR");return null;}
            node = hasNext(oid, node.children);
            while(node.children != null && node.children.size() > 0){
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
        OID oid = vb.getOid();
        Node aux = root;
        for(int i = 1; i < oid.size(); i++){
            aux = findNode(aux.children, oid.get(i), i);
        }
        aux.data.setVariable(vb.getVariable());
    }

    private Node findNode(List<Node> list, int oid, int i){
        for(Node n : list){
            if(n.data.getOid().get(i) == oid) return n;
        }
        return null;
    }

}
