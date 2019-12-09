package com.crypho.plugins;

import android.content.Context;

import android.util.Log;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONException;

import java.util.HashMap;
import java.util.Map;

public class SecureStorage extends CordovaPlugin {
    private static final String TAG = "SecureStorage";

    private Map<String,SecurePreferences> storageList = new HashMap<String, SecurePreferences>();

    @Override
    public boolean execute(String action, CordovaArgs args, final CallbackContext callbackContext) throws JSONException {
        if ("init".equals(action)) {
            try {
                String serviceName = args.getString(0);
                String encryptionKey = args.getString(1);
                storageList.put(serviceName, new SecurePreferences(getContext(), serviceName));
                if (!RSA.isEntryAvailable(serviceName)) {
                    RSA.createKeyPair(getContext(), serviceName);
                }
                callbackContext.success();
            } catch (Exception e) {
                callbackContext.error(e.getMessage());
            }

            return true;
        }
        else if ("set".equals(action)) {
            final String service = args.getString(0);
            final String key = args.getString(1);
            final String value = args.getString(2);

            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        if(storageList.containsKey(service)) {
                            SecurePreferences.Editor editor = storageList.get(service).edit();
                            editor.setServiceName(service);
                            editor.putString(key, value);
                            editor.commit();

                            callbackContext.success();
                        }
                        else {
                            callbackContext.error("Storage is not initialized");
                        }
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        else if ("get".equals(action)) {
            final String service = args.getString(0);
            final String key = args.getString(1);

            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        if(storageList.containsKey(service)) {
                            SecurePreferences securePreferences = storageList.get(service);
                            securePreferences.setServiceName(service);
                            String value = securePreferences.getString(key, "");
                            callbackContext.success(value);
                        }
                        else {
                            callbackContext.error("Storage is not initialized");
                        }
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        else if ("remove".equals(action)) {
            final String service = args.getString(0);
            final String key = args.getString(1);

            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        if(storageList.containsKey(service)) {
                            SecurePreferences.Editor editor = storageList.get(service).edit();
                            editor.setServiceName(service);
                            editor.putString(key, "");
                            editor.commit();

                            callbackContext.success();
                        }
                        else {
                            callbackContext.error("Storage is not initialized");
                        }
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        return false;
    }

    private Context getContext(){
        return cordova.getActivity().getApplicationContext();
    }

    private void initSuccess(CallbackContext context) {
        context.success();
    }
}