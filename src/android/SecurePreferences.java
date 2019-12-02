/*
 * Copyright (C) 2015, Scott Alexander-Bown, Daniel Abraham
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.crypho.plugins;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Wrapper class for Android's {@link SharedPreferences} interface, which adds a
 * layer of encryption to the persistent storage and retrieval of sensitive
 * key-value pairs of primitive data types.
 * <p>
 * This class provides important - but nevertheless imperfect - protection
 * against simple attacks by casual snoopers. It is crucial to remember that
 * even encrypted data may still be susceptible to attacks, especially on rooted devices
 * <p>
 * Recommended to use with user password, in which case the key will be derived from the password and not stored in the file.
 *
 * TODO: Handle OnSharedPreferenceChangeListener
 */
public class SecurePreferences implements SharedPreferences {

    //the backing pref file
    private SharedPreferences sharedPreferences;
    private String serviceName;

    private static boolean sLoggingEnabled = false;

    private static final String TAG = SecurePreferences.class.getName();

    //name of the currently loaded sharedPrefFile, can be null if default
    private String sharedPrefFilename;


    /**
     * User password defaults to app generated password that's stores obfucated with the other preference values. Also this uses the Default shared pref file
     *
     * @param context should be ApplicationContext not Activity
     */
    public SecurePreferences(Context context) {
        this(context, null);
    }

    public SecurePreferences(Context context, final String sharedPrefFilename) {
        if (sharedPreferences == null) {
            sharedPreferences = getSharedPreferenceFile(context, sharedPrefFilename);
        }
    }



    /**
     * if a prefFilename is not defined the getDefaultSharedPreferences is used.
     * @param context
     * @return
     */
    private SharedPreferences getSharedPreferenceFile(Context context, String prefFilename) {
        this.sharedPrefFilename = sharedPrefFilename;

        if(TextUtils.isEmpty(prefFilename)) {
            return PreferenceManager
                    .getDefaultSharedPreferences(context);
        }
        else{
            return context.getSharedPreferences(prefFilename, Context.MODE_PRIVATE);
        }
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    private String encryptValue(String cleartext, String serviceName) {
        try {
            String value = cleartext;
            JSONObject result = AES.encrypt(value.getBytes(), serviceName.getBytes());
            byte[] aes_key = Base64.decode(result.getString("key"), Base64.DEFAULT);
            byte[] aes_key_enc = RSA.encrypt(aes_key, serviceName);
            result.put("key", Base64.encodeToString(aes_key_enc, Base64.DEFAULT));
            return result.toString();
        } catch (Exception e) {
            Log.e(TAG, "Encrypt failed :", e);
            return null;
        }
    }

    /**
     *
     * @param ciphertext
     * @return decrypted plain text, unless decryption fails, in which case null
     */
    private String decrypt(final String ciphertext, final String serviceName) {
        try {
            JSONObject json = new JSONObject(ciphertext);
            final byte[] encKey = Base64.decode(json.getString("key"), Base64.DEFAULT);
            JSONObject data = json.getJSONObject("value");
            final byte[] ct = Base64.decode(data.getString("ct"), Base64.DEFAULT);
            final byte[] iv = Base64.decode(data.getString("iv"), Base64.DEFAULT);
            final byte[] adata = Base64.decode(data.getString("adata"), Base64.DEFAULT);
            byte[] decryptedKey = RSA.decrypt(encKey, serviceName);
            String decrypted = new String(AES.decrypt(ct, decryptedKey, iv, adata));
            return decrypted;
        } catch (Exception e) {
            Log.e(TAG, "Decrypt failed :", e);
            return null;
        }
    }

    /**
     *
     * @return map of with decrypted values (excluding the key if present)
     */
    @Override
    public Map<String, String> getAll() {
        return null;
    }

    @Override
    public String getString(String key, String defaultValue) {
        final String encryptedValue = sharedPreferences.getString(key, null);
        return (encryptedValue != null) ? decrypt(encryptedValue, this.serviceName) : defaultValue;
    }

    @Override
    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    public Set<String> getStringSet(String key, Set<String> defaultValues) {
        final Set<String> encryptedSet = sharedPreferences.getStringSet(key, null);
        if (encryptedSet == null) {
            return defaultValues;
        }
        final Set<String> decryptedSet = new HashSet<String>(
                encryptedSet.size());
        for (String encryptedValue : encryptedSet) {
            decryptedSet.add(decrypt(encryptedValue, this.serviceName));
        }
        return decryptedSet;
    }

    @Override
    public int getInt(String key, int defaultValue) {
        final String encryptedValue = sharedPreferences.getString(key, null);
        if (encryptedValue == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(decrypt(encryptedValue, this.serviceName));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public long getLong(String key, long defaultValue) {
        final String encryptedValue = sharedPreferences.getString(key, null);
        if (encryptedValue == null) {
            return defaultValue;
        }
        try {
            return Long.parseLong(decrypt(encryptedValue, this.serviceName));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public float getFloat(String key, float defaultValue) {
        final String encryptedValue = sharedPreferences.getString(key, null);
        if (encryptedValue == null) {
            return defaultValue;
        }
        try {
            return Float.parseFloat(decrypt(encryptedValue, this.serviceName));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public boolean getBoolean(String key, boolean defaultValue) {
        final String encryptedValue = sharedPreferences.getString(key, null);
        if (encryptedValue == null) {
            return defaultValue;
        }
        try {
            return Boolean.parseBoolean(decrypt(encryptedValue, this.serviceName));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public boolean contains(String key) {
        return sharedPreferences.contains(key);
    }

    @Override
    public Editor edit() {
        return new Editor();
    }

    /**
     * Wrapper for Android's {@link android.content.SharedPreferences.Editor}.
     * <p>
     * Used for modifying values in a {@link SecurePreferences} object. All
     * changes you make in an editor are batched, and not copied back to the
     * original {@link SecurePreferences} until you call {@link #commit()} or
     * {@link #apply()}.
     */
    public class Editor implements SharedPreferences.Editor {
        private SharedPreferences.Editor mEditor;
        private String serviceName;

        /**
         * Constructor.
         */
        private Editor() {
            mEditor = sharedPreferences.edit();
            serviceName = "";
        }

        public void setServiceName(String serviceName) {
            this.serviceName = serviceName;
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            mEditor.putString(key, encryptValue(value, this.serviceName));
            return this;
        }

        /**
         * This is useful for storing values that have be encrypted by something
         * else or for testing
         *
         * @param key
         *            - encrypted as usual
         * @param value
         *            will not be encrypted
         * @return
         */
        public SharedPreferences.Editor putUnencryptedString(String key,  String value) {
            mEditor.putString(key, value);
            return this;
        }

        @Override
        @TargetApi(Build.VERSION_CODES.HONEYCOMB)
        public SharedPreferences.Editor putStringSet(String key,
                                                     Set<String> values) {
            final Set<String> encryptedValues = new HashSet<String>(
                    values.size());
            for (String value : values) {
                encryptedValues.add(encryptValue(value, this.serviceName));
            }
            mEditor.putStringSet(key, encryptedValues);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            mEditor.putString(key, encryptValue(Integer.toString(value), this.serviceName));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            mEditor.putString(key, encryptValue(Long.toString(value), this.serviceName));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            mEditor.putString(key, encryptValue(Float.toString(value), this.serviceName));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            mEditor.putString(key, encryptValue(Boolean.toString(value), this.serviceName));
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            mEditor.remove(key);
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            mEditor.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return mEditor.commit();
        }

        @Override
        @TargetApi(Build.VERSION_CODES.GINGERBREAD)
        public void apply() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.GINGERBREAD) {
                mEditor.apply();
            } else {
                commit();
            }
        }
    }

    public static boolean isLoggingEnabled() {
        return sLoggingEnabled;
    }

    public static void setLoggingEnabled(boolean loggingEnabled) {
        sLoggingEnabled = loggingEnabled;
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(
            final OnSharedPreferenceChangeListener listener) {
        sharedPreferences
                .registerOnSharedPreferenceChangeListener(listener);
    }

    /**
     * @param listener OnSharedPreferenceChangeListener
     * @param decryptKeys Callbacks receive the "key" parameter decrypted
     */
    public void registerOnSharedPreferenceChangeListener(
            final OnSharedPreferenceChangeListener listener, boolean decryptKeys) {

        if(!decryptKeys) {
            registerOnSharedPreferenceChangeListener(listener);
            return;
        }
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(
            OnSharedPreferenceChangeListener listener) {

        sharedPreferences
                .unregisterOnSharedPreferenceChangeListener(listener);
    }
}