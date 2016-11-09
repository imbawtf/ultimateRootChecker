# ultimateRootChecker
ultimateRootChecker - we will find root ;)

https://play.google.com/store/apps/details?id=wtf.imba.ultimaterootchecker

http://forum.xda-developers.com/xposed/discussion-ultimate-root-checking-t3497070


We have come across an interesting problem, that renders lost all our labours with such apps as rootCloak, hideRoot (along with personal efforts and accessory methods) and makes us exposed to systems.

We created a small app, called it ultimateRootChecker (links  will in the end of post). It uses multiple methods for root check, the most interesting of them (granted Xposed is present) being the analysis of Log.getStackTraceString for XposedBridge string, that would be present everywhere where there is Xposed or Cydia.

```java
private boolean additionSystemRootFramework() {
        try {
            Runtime.getRuntime().exec("su");
        } catch (Exception ignored) {}
        String stackTrace = Log.getStackTraceString(new Throwable());
        return stackTrace.contains("xposed") || stackTrace.contains("substrate");
    }
```
As experience has shown, anyone can access this log. Fabric(Crashlytics), for instance, sends this data back to themselves for processing and analysis. The same practice is adopted by a couple of mobile ad networks, and I think they do it for their antiFraud machines. Yes, it is possible to search for these classes during every assembling or change of the app and replace it with Xposed, but maybe you have better and more elegant solutions?

In the meantime, feel free to test our app on your devices and share means of traversal of our verification.
If you have any other methods of verification, your pull-requests would be appreciated.
