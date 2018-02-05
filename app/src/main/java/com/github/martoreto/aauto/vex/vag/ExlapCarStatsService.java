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
import com.github.martoreto.aauto.vex.ICarStats;
import com.github.martoreto.aauto.vex.ICarStatsListener;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
        for (ExlapReader r: mExlapReaders) {
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
            for (ExlapReaderAdapter adapter: mExlapReaderAdapters) {
                try {
                    adapter.startNewSession();
                } catch (Exception e) {
                    Log.e(TAG, adapter.mName + ": Error handling car connection", e);
                }
            }
        }

        @Override
        public void onDisconnected() throws RemoteException {
            for (ExlapReaderAdapter adapter: mExlapReaderAdapters) {
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
            for (ExlapReader r: mExlapReaders) {
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
    };

    @Override
    public void onExlapMeasurements(ExlapReader reader, ExlapReader.MeasurementsBundle measurements) {
        try {
            final int n = mListeners.beginBroadcast();
            for (int i = 0; i < n; i++) {
                ICarStatsListener listener = mListeners.getBroadcastItem(i);
                try {
                    listener.onNewMeasurements(measurements.getTimestamp().getTime(),
                            measurements.getValues());
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
            mSessionId = null;
            dispatchStop();
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
                    }
                }
            });
        }
    }
}
