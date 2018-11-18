package com.github.martoreto.aauto.vex.vag;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.support.annotation.Nullable;
import android.util.Log;

import com.github.martoreto.aauto.exlap.IExlapService;
import com.github.martoreto.aauto.exlap.IExlapServiceListener;
import com.github.martoreto.aauto.exlap.IExlapSessionListener;
import com.github.martoreto.aauto.vex.FieldSchema;
import com.github.martoreto.aauto.vex.ICarStats;
import com.github.martoreto.aauto.vex.ICarStatsListener;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExlapCarStatsService extends Service implements ExlapReader.Listener {
    private static final String TAG = "ExlapCarStatsService";

    private static final int[] SESSION_AUTHS = {
            ExlapReader.AUTH_RSE_3,
    };

    private static final String[] SESSION_NAMES = {
            "stats",
    };

    private IExlapService mExlapSessionService;
    private final Handler mExlapHandler = new Handler();
    private RemoteCallbackList<ICarStatsListener> mListeners = new RemoteCallbackList<>();
    private List<ExlapReaderAdapter> mExlapReaderAdapters = new ArrayList<>();
    private List<ExlapReader> mExlapReaders = new ArrayList<>();
    private Map<String, FieldSchema> mSchema = Collections.emptyMap();
    private Set<String> mUnitKeys = Collections.emptySet();

    @Override
    public void onCreate() {
        super.onCreate();

        for (int i = 0; i < SESSION_AUTHS.length; i++) {
            ExlapReaderAdapter adapter = new ExlapReaderAdapter(SESSION_NAMES[i]);
            ExlapReader reader = new ExlapReader(this, adapter, SESSION_AUTHS[i]);
            reader.registerListener(this);
            mExlapReaders.add(reader);
            mExlapReaderAdapters.add(adapter);
        }

        Intent intent = new Intent(this, ExlapSessionService.class);
        bindService(intent, mServiceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    public void onDestroy() {
        unbindService(mServiceConnection);
        for (ExlapReader r : mExlapReaders) {
            r.unregisterListener(this);
        }
        super.onDestroy();
    }

    private final ServiceConnection mServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName componentName, IBinder binder) {
            mExlapSessionService = IExlapService.Stub.asInterface(binder);
            try {
                mExlapSessionService.registerListener(mExlapServiceListener);
            } catch (RemoteException e) {
                Log.e(TAG, "Cannot register proxy listener", e);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            mExlapSessionService = null;
        }
    };

    private final IExlapServiceListener mExlapServiceListener = new IExlapServiceListener.Stub() {
        @Override
        public void onConnected() throws RemoteException {
            for (ExlapReaderAdapter adapter : mExlapReaderAdapters) {
                try {
                    adapter.startNewSession();
                } catch (Exception e) {
                    Log.e(TAG, adapter.mName + ": Error handling car connection", e);
                }
            }
        }

        @Override
        public void onDisconnected() throws RemoteException {
            for (ExlapReaderAdapter adapter : mExlapReaderAdapters) {
                try {
                    adapter.onDisconnect();
                } catch (Exception e) {
                    Log.e(TAG, adapter.mName + ": Error handling car disconnection", e);
                }
            }
        }
    };

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private final ICarStats.Stub mBinder = new ICarStats.Stub() {
        @Override
        public void registerListener(final ICarStatsListener listener) throws RemoteException {
            mListeners.register(listener);
        }

        @Override
        public void unregisterListener(final ICarStatsListener listener) throws RemoteException {
            mListeners.unregister(listener);
        }

        @Override
        public Map getMergedMeasurements() throws RemoteException {
            Map<String, Object> result = new HashMap<>();
            for (ExlapReader r : mExlapReaders) {
                result.putAll(r.getMergedMeasurements());
            }
            return result;
        }

        @Override
        public boolean needsPermissions() throws RemoteException {
            return ExlapProxyService.needsPermissions(ExlapCarStatsService.this);
        }

        @Override
        public void requestPermissions() throws RemoteException {
            ExlapProxyService.requestPermissions(ExlapCarStatsService.this);
        }

        @Override
        public Map getSchema() throws RemoteException {
            return mSchema;
        }
    };

    private static String mainKeyForUnitField(Map<String, FieldSchema> schema, String key) {
        String mainKey = null;
        if (key.endsWith(".unit")) {
            mainKey = key.substring(0, key.length() - ".unit".length());
        } else if (key.endsWith("Unit")) {
            mainKey = key.substring(0, key.length() - "Unit".length());
        }
        if (mainKey != null && schema.containsKey(mainKey)) {
            return mainKey;
        } else {
            return null;
        }
    }

    @Override
    public void onNewSchema(Map<String, ExlapReader.MeasurementSchema> schema) {
        Map<String, FieldSchema> oldSchema = mSchema;
        Map<String, FieldSchema> newSchema = new HashMap<>(schema.size());
        Set<String> unitKeys = new HashSet<>();

        for (Map.Entry<String, ExlapReader.MeasurementSchema> e : schema.entrySet()) {
            ExlapReader.MeasurementSchema s = e.getValue();
            int newType;
            switch (s.getType()) {
                case STRING:
                    newType = FieldSchema.TYPE_STRING;
                    break;
                case INTEGER:
                    newType = FieldSchema.TYPE_INTEGER;
                    break;
                case FLOAT:
                    newType = FieldSchema.TYPE_FLOAT;
                    break;
                case BOOLEAN:
                    newType = FieldSchema.TYPE_BOOLEAN;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown type");
            }
            newSchema.put(e.getKey(), new FieldSchema(newType, s.getDescription(), s.getUnit(),
                    s.getMin(), s.getMax(), s.getResolution()));
        }

        Iterator<Map.Entry<String, FieldSchema>> iter = newSchema.entrySet().iterator();
        while (iter.hasNext()) {
            String key = iter.next().getKey();
            String mainKey = mainKeyForUnitField(newSchema, key);
            if (mainKey != null && newSchema.get(mainKey).getUnit() == null) {
                iter.remove();
                unitKeys.add(key);
                FieldSchema newFieldSchema = newSchema.get(mainKey);
                FieldSchema oldFieldSchema = oldSchema.get(mainKey);
                if (newFieldSchema != null && newFieldSchema.getUnit() == null
                        && oldFieldSchema != null && oldFieldSchema.getUnit() != null) {
                    newSchema.put(mainKey, new FieldSchema(newFieldSchema.getType(),
                            newFieldSchema.getDescription(), oldFieldSchema.getUnit(),
                            newFieldSchema.getMin(), newFieldSchema.getMax(),
                            newFieldSchema.getResolution()));
                }
            }
        }

        Log.d(TAG, "New schema.");

        mSchema = newSchema;
        mUnitKeys = unitKeys;
        dispatchSchemaChanged();
    }

    private void dispatchSchemaChanged() {
        try {
            final int n = mListeners.beginBroadcast();
            for (int i = 0; i < n; i++) {
                ICarStatsListener listener = mListeners.getBroadcastItem(i);
                try {
                    listener.onSchemaChanged();
                } catch (RemoteException re) {
                    // ignore
                }
            }
        } finally {
            mListeners.finishBroadcast();
        }
    }

    @Override
    public void onExlapMeasurements(ExlapReader reader, ExlapReader.MeasurementsBundle measurements) {
        HashMap<String, Object> values = new HashMap<>(measurements.getValues());

        try {
            Iterator<Map.Entry<String, Object>> iter = values.entrySet().iterator();
            boolean schemaChanged = false;
            while (iter.hasNext()) {
                Map.Entry<String, Object> entry = iter.next();
                String key = entry.getKey();
                if (mUnitKeys.contains(key)) {
                    String unit = (String) entry.getValue();
                    String mainKey = mainKeyForUnitField(mSchema, key);
                    //Log.v(TAG, "Adj: " + key + " -> " + mainKey);
                    FieldSchema fieldSchema = mSchema.get(mainKey);
                    if (unit != null && !unit.equals(fieldSchema.getUnit())) {
                        mSchema.put(mainKey, new FieldSchema(fieldSchema.getType(),
                                fieldSchema.getDescription(), unit, fieldSchema.getMin(),
                                fieldSchema.getMax(), fieldSchema.getResolution()));
                        schemaChanged = true;
                    }
                    iter.remove();
                }
            }
            if (schemaChanged) {
                dispatchSchemaChanged();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error adjusting schema", e);
        }

        dispatchMeasurements(measurements.getTimestamp().getTime(), values);
    }

    private void dispatchMeasurements(long ts, Map<String, Object> values) {
        try {
            final int n = mListeners.beginBroadcast();
            for (int i = 0; i < n; i++) {
                ICarStatsListener listener = mListeners.getBroadcastItem(i);
                try {
                    listener.onNewMeasurements(ts, values);
                } catch (RemoteException re) {
                    // ignore
                }
            }
        } finally {
            mListeners.finishBroadcast();
        }
    }

    private class ExlapReaderAdapter extends ExlapReader.Adapter {
        private final String mName;
        private String mSessionId;

        ExlapReaderAdapter(String name) {
            this.mName = name;
        }

        void onDisconnect() {
            try {
                mSessionId = null;
                dispatchStop();
            } catch (Exception e) {
                Log.e(TAG, mName + ": Error handling disconnection", e);
            }
        }

        void startNewSession() throws RemoteException {
            if (mExlapSessionService == null) {
                Log.w(TAG, mName + ": No session service, not starting session.");
                return;
            }
            mSessionId = ExlapUtils.generateSessionId();
            mExlapSessionService.registerSession(mSessionId, mSessionListener);
            dispatchStart(mSessionId);
        }

        @Override
        protected void restart() {
            if (mSessionId == null) {
                Log.d(TAG, mName + ": Not restarting, as we are not even connected...");
                return;
            }
            try {
                mExlapSessionService.unregisterSession(mSessionId);
                startNewSession();
            } catch (Exception e) {
                Log.e(TAG, mName + ": Error restarting session", e);
            }
        }

        private final IExlapSessionListener mSessionListener = new IExlapSessionListener.Stub() {
            @Override
            public void onData(byte[] data) throws RemoteException {
                dispatchData(ByteBuffer.wrap(data));
            }
        };

        @Override
        protected void send(ByteBuffer data) throws IOException {
            if (mSessionId == null) {
                Log.d(TAG, mName + ": Not sending data, as we don't have a session");
                return;
            }
            final byte[] bytes = new byte[data.remaining()];
            data.get(bytes);
            mExlapHandler.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        mExlapSessionService.sendData(bytes);
                    } catch (Exception e) {
                        Log.e(TAG, mName + ": Error sending Exlap data", e);
                        onDisconnect();
                    }
                }
            });
        }
    }
}
