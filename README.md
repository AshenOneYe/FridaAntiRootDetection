# FridaAntiRootDetection
A frida script for bypass common root detection,the collection of detection methods is still improving！

![demo](demo.jpg)

## Usage

### Directly use js
```
frida -UF -l antiroot.js
```

OR

### Enable child-gatting by python
modify the `target` variable and run
```
python antiroot.py 
```