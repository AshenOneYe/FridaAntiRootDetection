const commonPaths = [
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/failsafe/su",
            "/system/bin/su",
            "/su/bin/su",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/sd/xbin/su",
            "/system/xbin/busybox",
            "/system/xbin/daemonsu",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/app/Kinguser.apk",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple",
            "/init.magisk.rc",
            "/system/xbin/ku.sud"
          ];

const ROOTmanagementApp = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk"
          ];



function stackTraceHere(){
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    console.log(Log.getStackTraceString(Exception.$new()))
}


function bypassJavaFileCheck(){
    var File = Java.use('java.io.File')

    File.exists.implementation = function(){
    
        const filename = this.getAbsolutePath();

        if (filename.indexOf("magisk") >= 0) {
            console.log("Anti Root Detect - File exists: " + filename)
            // stackTraceHere()
            return false;
        }

        if (commonPaths.indexOf(filename) >= 0) {
            console.log("Anti Root Detect - File exists: " + filename)
            // stackTraceHere()
            return false;
        }
        return this.exists.call(this);
    }

    File.canExecute.implementation = function(){
        const filename = this.getAbsolutePath();

        if (filename.indexOf("magisk") >= 0) {
            console.log("Anti Root Detect - File exists: " + filename)
            // stackTraceHere()
            return false;
        }

        if (commonPaths.indexOf(filename) >= 0) {
            console.log("Anti Root Detect - File canExecute: " + filename)
            return false;
        }
        return this.canExecute.call(this);
    }
}

function bypassNativeFileCheck(){
    var fopen = Module.findExportByName("libc.so","fopen")
    Interceptor.attach(fopen,{
        onEnter:function(args){
            this.inputPath = args[0].readUtf8String()
        },
        onLeave:function(retval){
            if(retval.toInt32() != 0){
                if (commonPaths.indexOf(this.inputPath) >= 0) {
                    console.log("Anti Root Detect - fopen : " + this.inputPath)
                    retval.replace(ptr(0x0))
                }
            }
        }
    })
}

function setReleaseKey(){
    Java.use("android.os.Build").TAGS.value = "release-keys"
    //TODO
}

//android.app.PackageManager
function bypassRootAppCheck(){
    var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager")
    ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str,i){
        // console.log(str)
        if (ROOTmanagementApp.indexOf(str) >= 0) {
            console.log("Anti Root Detect - check package : " + str)
            str = "ashen.one.ye.not.found"
        }
        return this.getPackageInfo(str,i)
    }
}

function bypassShellCheck(){
    var String = Java.use('java.lang.String');
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder")
    ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(strs){

        if(strs[0] == "mount"){
            console.log("Anti Root Detect - Runtime : " + strs.toString())
            this.$init(Java.array('java.lang.String',[String.$new("")]))
        }


        if(strs[0] == "getprop"){
            console.log("Anti Root Detect -  ProcessBuilder : " + strs.toString())
            const prop = [
                "ro.secure",
                "ro.debuggable"
              ];
            if(prop.indexOf(strs[1]) >= 0){
                this.$init(Java.array('java.lang.String',[String.$new("")]))
                return
            }
        }

        if(strs[0] == "which" || strs[0] == "/system/xbin/which"){
            const prop = [
                "su"
              ];
            if(prop.indexOf(strs[1]) >= 0){
                console.log("Anti Root Detect -  ProcessBuilder : " + strs.toString())
                this.$init(Java.array('java.lang.String',[String.$new("")]))
                return
            }
        }

        this.$init(strs)
    }

    var Runtime = Java.use("java.lang.Runtime")
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(strs){
        
        if(strs[0] == "mount"){
            console.log("Anti Root Detect - Runtime : " + strs.toString())
            return this.exec(Java.array('java.lang.String',[String.$new("")]))
        }

        if(strs[0] == "getprop"){
            console.log("Anti Root Detect - Runtime : " + strs.toString())
            const prop = [
                "ro.secure",
                "ro.debuggable"
              ];
            if(prop.indexOf(strs[1]) >= 0){
                return this.exec(Java.array('java.lang.String',[String.$new("")]))
            }
        }

        if(strs[0] == "which" || strs[0] == "/system/xbin/which"){
            const prop = [
                "su"
              ];
            if(prop.indexOf(strs[1]) >= 0){
                console.log("Anti Root Detect - Runtime : " + strs.toString())
                return this.exec(Java.array('java.lang.String',[String.$new("")]))
            }
        }

        return this.exec(strs)
    }


}



Java.perform(function(){

    bypassJavaFileCheck()
    bypassNativeFileCheck()
    setReleaseKey()
    bypassRootAppCheck()
    bypassShellCheck()

})


/**
 *  private boolean checkRootProp() {
        try {
            InputStream v1_1 = this.invokeRuntimeExec(new String[]{"getprop"});
            if(v1_1 == null) {
                return 0;
            }

            String[] v1_2 = new Scanner(v1_1).useDelimiter("\\A").next().split("\n");
            if(v1_2 != null) {
                HashMap v2 = new HashMap();
                v2.put("ro.debuggable", "1");
                v2.put("ro.secure", "0");
                int v4 = 0;
                while(true) {
                    if(v4 >= v1_2.length) {
                        return 0;
                    }

                    String v5 = v1_2[v4];
                    Iterator v6 = v2.keySet().iterator();
                    while(true) {
                    label_28:
                        if(!v6.hasNext()) {
                            ++v4;
                            break;
                        }

                        Object v7 = v6.next();
                        String v7_1 = (String)v7;
                        if(v5 == null || !v5.contains(v7_1)) {
                            goto label_28;
                        }

                        boolean v7_2 = v5.contains("[" + v2.get(v7_1) + "]");
                        goto label_50;
                    }
                }
            }
        }
        catch(Throwable v1) {
            MobLog.getInstance().w(v1);
        }

        return 0;
    label_50:
        if(!v7_2) {
            goto label_28;
        }

        return 1;
    }
 */


/**
 * 模拟器检测
 * public static boolean b() {
        return (Build.FINGERPRINT.startsWith("generic")) || (Build.FINGERPRINT.toLowerCase().contains("vbox")) || (Build.FINGERPRINT.toLowerCase().contains("test-keys")) || (Build.MODEL.contains("google_sdk")) || (Build.MODEL.contains("Emulator")) || (Build.MODEL.contains("Android SDK built for x86")) || (Build.MANUFACTURER.contains("Genymotion")) || (Build.BRAND.startsWith("generic")) && (Build.DEVICE.startsWith("generic")) || ("google_sdk".equals(Build.PRODUCT));
    }

 * 
    public static boolean a() {
        BluetoothAdapter v0 = BluetoothAdapter.getDefaultAdapter();
        if(v0 == null) {
            return 1;
        }

        return TextUtils.isEmpty(v0.getName()) ? 1 : 0;
    }

    public static boolean c() {
        String v0 = b.d();
        return (v0.contains("intel")) || (v0.contains("amd")) ? 1 : 0;
    }
 */