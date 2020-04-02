## Self inject

#### This project is a little poc of a manual memory mapper.
#### It downloads a dll via HTTP and maps the section into memory.
#### After calling CreateThread on the loaded DLL, selfinject will look for the first entry in the Export table and call it.

##### How to use this poc:

* Change the hardcoded Hostnames in both selfinject (main function) and callHome(doStuff function) to point to your http server.
* Compile both Projects
* Copy the cmd file and the callHome.dll into the base directory of your http server
* Restart your http server
* Execute selfinject.exe (this will probably alarm your windows defender since it does correctly identify this as a dropper)
* You can also just run it from Visual Studio so u wont have to worry about Windows Defender


![PoC](/POC.PNG)

