package wtf.imba.ultimaterootchecker;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Scanner;

class RootChecker {

    private final Context mContext;
    private Map<String, String> values = new HashMap<>();

    RootChecker(Context context) {
        mContext = context;
    }

    boolean check(String identifier) {
        switch (identifier) {
            case "su Managers":
                return suManagers();
            case "su Binary":
                return binaries("su");
            case "busybox Binary":
                return binaries("busybox");
            case "dangerous Build.prop values":
                return buildPropChecker();
            case "rw System Folders":
                return rwRules();
            case "test-keys":
                return roBuildChecker();
            case "check Su Exists":
                return checkSuExists();
            case "detect Root Hiders":
                return rootHiders();
            case "Xposed or Cydia":
                return additionSystemRootFramework();
        }
        return false;
    }

    public String getRootReason(String key) {
        if (values.containsKey(key)) {
            return values.get(key);
        }
        return null;
    }

    private boolean additionSystemRootFramework() {
        try {
            Runtime.getRuntime().exec("su");
        } catch (Exception ignored) {}
        String stackTrace = Log.getStackTraceString(new Throwable());
        StringBuilder val = new StringBuilder();
        if (stackTrace.contains("xposed")) val.append("xposed \n");
        if (stackTrace.contains("substrate")) val.append("substrate \n");
        if (!val.toString().isEmpty()) {
            val.append("finding in StackTrace");
            values.put("Xposed or Cydia", val.toString());
        }
        return stackTrace.contains("xposed") || stackTrace.contains("substrate");
    }

    private boolean roBuildChecker() {
        StringBuilder val = new StringBuilder();
        if (android.os.Build.TAGS != null && android.os.Build.TAGS.contains("test-keys")){
            val.append("'test-keys' find in android.os.Build.TAGS");
            values.put("test-keys", val.toString());
        }
        return android.os.Build.TAGS != null && android.os.Build.TAGS.contains("test-keys");
    }

    private boolean suManagers() {
        return suManagers(null, "su Managers");
    }

    private boolean suManagers(String[] additionalRootManagementApps, String key) {
        List<String> packages = Arrays.asList(
                "com.noshufou.android.su",
                "com.noshufou.android.su.elite",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.thirdparty.superuser",
                "com.yellowes.su",
                "eu.chainfire.supersu.pro"
        );
        if (additionalRootManagementApps != null && additionalRootManagementApps.length > 0){
            packages.addAll(Arrays.asList(additionalRootManagementApps));
        }
        return pmManager(packages, key);
    }

    private boolean rootHiders() {
        return rootHiders(null, "detect Root Hiders");
    }

    private boolean rootHiders(String[] additionalRootCloakingApps, String key) {
        List<String> packages = Arrays.asList("com.devadvance.rootcloak",
                "de.robv.android.xposed.installer",
                "com.saurik.substrate",
                "com.devadvance.rootcloakplus",
                "com.amphoras.hidemyroot",
                "com.formyhm.hideroot",
                "com.loserskater.suhidegui"
        );
        if (additionalRootCloakingApps != null && additionalRootCloakingApps.length>0){
            packages.addAll(Arrays.asList(additionalRootCloakingApps));
        }
        return pmManager(packages, key);
    }

    private String[] propsReader() {
        try {
            InputStream inputstream = Runtime.getRuntime().exec("getprop").getInputStream();
            if (inputstream == null) {
                return null;
            }
            return new Scanner(inputstream).useDelimiter("\\A").next().split("\n");
        } catch (IOException | NoSuchElementException ignored) {
            return null;
        }
    }

    private String[] mountReader() {
        try {
            InputStream inputstream = Runtime.getRuntime().exec("mount").getInputStream();

            if (inputstream == null) return null;

            return new Scanner(inputstream).useDelimiter("\\A").next().split("\n");
        } catch (IOException |NoSuchElementException e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean pmManager(List<String> packages, String key){
        boolean result = false;

        PackageManager pm = mContext.getPackageManager();
        StringBuilder val = new StringBuilder();
        for (String packageName : packages) {
            try {
                pm.getPackageInfo(packageName, 0);
                val.append(packageName).append("\n");
                result = true;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        if (!val.toString().isEmpty()) values.put(key, val.toString());
        return result;
    }

    private boolean buildPropChecker() {

        final Map<String, String> badBProps = new HashMap<>();
        badBProps.put("ro.debuggable", "1");
        badBProps.put("ro.secure", "0");
        badBProps.put("ro.build.selinux", "0");

        boolean result = false;

        String[] lines = propsReader();
        if (lines == null) {
            return false;
        }
        StringBuilder val = new StringBuilder();
        for (String line : lines) {
            for (String key : badBProps.keySet()) {
                if (line.contains(key)) {
                    if (line.contains(String.format("[%s]", badBProps.get(key)))) {
                        val.append(line).append("\n");
                        result = true;
                    }
                }
            }
        }
        values.put("dangerous Build.prop values", val.toString());
        return result;
    }

    private boolean rwRules() {
        String[] lines = mountReader();
        if (lines == null) return false;

        for (String line : lines) {

            String[] args = line.split(" ");

            if (args.length < 4){
                continue;
            }
            String mountPoint = args[1];
            String mountOptions = args[3];

            List<String> path = Arrays.asList(
                    "/system",
                    "/system/bin",
                    "/system/sbin",
                    "/system/xbin",
                    "/vendor/bin",
                    "/sbin",
                    "/data"
            );

            StringBuilder val = new StringBuilder();
            for(String pathToCheck: path) {
                if (mountPoint.equalsIgnoreCase(pathToCheck)) {
                    for (String option : mountOptions.split(",")){
                        if (option.equalsIgnoreCase("rw")){
                            val.append(pathToCheck);
                            values.put("rw System Folders", val.toString());
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    private boolean checkSuExists() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[] { "/system/xbin/which", "su" });
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            boolean exist = in.readLine() != null;
            if (exist) {
                values.put("check Su Exists", "Runtime.getRuntime().exec(new String[] { \"/system/xbin/which\", \"su\" })");
            }
            return exist;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }

    private boolean binaries(String filename) {
        List<String> pathsArray = Arrays.asList(
                "/data/local/",
                "/data/local/bin/",
                "/data/local/xbin/",
                "/sbin/",
                "/system/bin/",
                "/system/sd/xbin/",
                "/system/xbin/",
                "/data/.super"
        );

        boolean result = false;
        StringBuilder val = new StringBuilder();
        for (String path : pathsArray) {
            String completePath = path + filename;
            File f = new File(completePath);
            boolean fileExists = f.exists();
            if (fileExists) {
                val.append(path).append("\n");
                result = true;
            }
        }
        if (!val.toString().isEmpty()) values.put(filename + " Binary", val.toString());
        return result;
    }
}
