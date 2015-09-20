Android-SNMP
============

This is a sample implementation of the Simple Network Management Protocol (SNMP) on Android devices.
We designed a Management Information Base (MIB) and implemented a desktop manager that queries devices on the network and an Android client that responds to queries.

### The MIB

![MIB tree](https://raw.githubusercontent.com/brnunes/Android-SNMP/master/MIB.jpg)

### How to use

- Run the client application (Agent.apk, or from code) on an Android device connected to the same Wi-Fi as the computer that will run the manager application. The application will start listening to requests on the port 32150.
- With the Agent running on the Android device, run the Manager (Android_SNMP_Manager.jar, or from code). It will try to detect the IP address of the local network and populate the range of IPs to be discovered (1). If it cannot detect the local network address range, it will use the range 192.168.0.1 to 192.168.0.254.
- Click the button "Discover". The application will send a query message to every IP in the range entered. For every response received, a device will be added to the list (2). You can add a new device by entering its IP address, edit the IP address of a device or remove a device from the list by using the buttons below it (3).
- When a device is selected on the list, the manager will query every MIB element and populate the device panel (4).
- The device panel shows the status of the device:
  * GPS status: ON, OFF
  * Wi-Fi status: ON, OFF
  * Bluetooth status: ON, OFF
  * Battery status: Charging, Discharging
  * Battery level: Percentage full
  * Device's manufacturer and model
  * Android version running
  * Up time
  * List of processes running: Process id, process name, running time, memory usage
- Clicking on any item on the panel will send a new request to the device and refresh its value.
- It is also possible to send a message to the device (5), that will appear on the the client application.

![Manager Application](https://raw.githubusercontent.com/brnunes/Android-SNMP/master/Screenshot_Manager.png)

- The client shows the messages received by managers on the top half of the screen, and logs the MIB queries on the bottom half.

![Client Application](https://raw.githubusercontent.com/brnunes/Android-SNMP/master/Screenshot_Client.png)
