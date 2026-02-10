forked on [wbenny/mini-tor](https://github.com/wbenny/mini-tor)  
trying to replace the fake crt by real crt and generate a static .lib  

refactoring a project that was write without the CRT.  
i want to use crt in it now.  
every include that starts with "<mini/something>" is a CRT substitute that needs to be replaced by the real crt.  
The original files are inside "original" folder.  