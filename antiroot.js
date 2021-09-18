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
            "com.ramdroid.appquarantinepro"
          ];




    

function bypassJavaFileCheck(){
    var File = Java.use('java.io.File')

    File.exists.implementation = function(){
        const filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0) {
            // console.log("Anti Root Detect - File not exists: " + filename)
            // stackTraceHere()
            return false;
        }
        return this.exists.call(this);
    }

    File.canExecute.implementation = function(){
        const filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0) {
            // console.log("Anti Root Detect - File not exists: " + filename)
        // stackTraceHere()
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
                    console.log("fopen : " + this.inputPath)
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

function bypassRootAppCheck(){
    var PackageManager = Java.use("android.content.pm.PackageManager")
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str,i){
        console.log(str)
        if (ROOTmanagementApp.indexOf(str) >= 0) {
            str = "ashen.one.ye.not.found"
            console.log("check package : " + str)
        }
        this.getPackageInfo(str,i)
    }
}

function bypassShellCheck(){
    var String = Java.use('java.lang.String');
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder")
    ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(strs){

        if(strs[0] == "getprop"){
            const prop = [
                "ro.secure",
                "ro.debuggable"
              ];
            if(prop.indexOf(strs[1]) >= 0){
                console.log("shell : " + strs.toString())
                this.$init(Java.array('java.lang.String',[String.$new("")]))
            }
        }

        if(strs[0] == "which"){
            const prop = [
                "su"
              ];
            if(prop.indexOf(strs[1]) >= 0){
                console.log("shell : " + strs.toString())
                this.$init(Java.array('java.lang.String',[String.$new("")]))
                return
            }
        }

        this.$init(strs)
    }
}



Java.perform(function(){


    bypassJavaFileCheck()
    bypassNativeFileCheck()
    setReleaseKey()
    bypassRootAppCheck()
    bypassShellCheck()

})