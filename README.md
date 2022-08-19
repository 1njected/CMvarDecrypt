# CMvarDecrypt

This tool can decrypt SCCM/ConfigMgr Variables.dat files with the default key "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}" or custom password.

Variables.dat files can sometimes be discoved on administrative shares and boot ISO's created with SCCM/ConfigMgr and can contain credentials such as domain join accounts.


Usage:
````
CMvarDecrypt.exe <Path to Variables.dat file>
CMvarDecrypt.exe <Path to Variables.dat file> <custom password>
````

PXETheif from MWR CyberSec can perform decryption and alot more:
https://github.com/MWR-CyberSec/PXEThief
