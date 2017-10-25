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
import com.github.martoreto.aauto.vex.IVexProxy;
import com.github.martoreto.aauto.vex.IVexProxyListener;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class ExlapSessionService extends Service {
    private static final String TAG = "ExlapSessionService";

    private static final int SESSION_TERMINATION_TIME_MS = 3000;

    private RemoteCallbackList<IExlapServiceListener> mServiceListeners;
    private Map<String, IExlapSessionListener> mSessionListeners;
    private Set<String> mRecentlyTerminatedSessions;

    private IVexProxy mVexService;
    private Handler mHandler;
    private boolean mIsConnected;
    private DocumentBuilder mDocumentBuilder;

    @Override
    public void onCreate() {
        super.onCreate();

        Log.d(TAG, "Service starting.");

        mServiceListeners = new RemoteCallbackList<>();
        mSessionListeners = new HashMap<>();
        mHandler = new Handler();
        mRecentlyTerminatedSessions = new HashSet<>();
        mIsConnected = false;

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setIgnoringComments(true);
        documentBuilderFactory.setNamespaceAware(false);
        documentBuilderFactory.setValidating(false);
        try {
            mDocumentBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }

        Intent intent = new Intent(this, ExlapProxyService.class);
        bindService(intent, mProxyServiceConnection, Context.BIND_AUTO_CREATE);
    }

    private final ServiceConnection mProxyServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName componentName, IBinder binder) {
            mVexService = IVexProxy.Stub.asInterface(binder);
            try {
                mVexService.registerListener(mVexListener);
            } catch (RemoteException e) {
                Log.e(TAG, "Cannot register proxy listener", e);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            mVexService = null;
        }
    };

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "Service stopping.");
        unbindService(mProxyServiceConnection);

        super.onDestroy();
    }

    private final IExlapService.Stub mBinder = new IExlapService.Stub() {
        @Override
        public void registerListener(final IExlapServiceListener listener) throws RemoteException {
            mServiceListeners.register(listener);

            // If we are already connected, we send the onConnected() event to the newly
            // registered listener.
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    if (mIsConnected) {
                        try {
                            listener.onConnected();
                        } catch (Exception e) {
                            Log.d(TAG, "Exception sending initial onConnected()", e);
                        }
                    }
                }
            });
        }

        @Override
        public void unregisterListener(final IExlapServiceListener listener) throws RemoteException {
            mServiceListeners.unregister(listener);
        }

        @Override
        public void registerSession(String sessionId, IExlapSessionListener listener) throws RemoteException {
            if (mSessionListeners.containsKey(sessionId)) {
                throw new IllegalArgumentException("Session already registered");
            }
            mSessionListeners.put(sessionId, listener);
        }

        @Override
        public void unregisterSession(String sessionId) throws RemoteException {
            if (!mSessionListeners.containsKey(sessionId)) {
                throw new IllegalArgumentException("Session not found");
            }
            mSessionListeners.remove(sessionId);
        }

        @Override
        public void sendData(byte[] data) throws RemoteException {
            mVexService.sendData(data);
        }
    };

    private final IVexProxyListener mVexListener = new IVexProxyListener.Stub() {
        @Override
        public void onConnected() throws RemoteException {
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    mIsConnected = true;
                    dispatchOnConnected();
                }
            });
        }

        @Override
        public void onData(final byte[] data) throws RemoteException {
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    dispatchOnData(data);
                }
            });
        }

        @Override
        public void onDisconnected() throws RemoteException {
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    mIsConnected = false;
                    mSessionListeners.clear();
                    dispatchOnDisconnected();
                }
            });
        }
    };

    private void dispatchOnData(byte[] data) {
        // TODO: buffering

        String xml = new String(data, StandardCharsets.UTF_8);
        Document doc;
        try {
            doc = mDocumentBuilder.parse(new InputSource(new StringReader(xml)));
        } catch (SAXException|IOException e) {
            Log.w(TAG, "Got unparsable XML", e);
            return;
        }
        Element root = doc.getDocumentElement();
        if (!root.hasAttribute("session_id")) {
            return;
        }

        String sessionId = root.getAttribute("session_id");
        IExlapSessionListener sessionListener = mSessionListeners.get(sessionId);
        if (sessionListener == null) {
            // No listener for this session.
            if (root.getTagName().equals("ExlapStatement")) {
                terminateSession(sessionId);
            }
            return;
        }

        try {
            sessionListener.onData(data);
        } catch (Exception e) {
            Log.d(TAG, "Exception from callback", e);
        }
    }

    private void terminateSession(String sessionId) {
        try {
            if (mRecentlyTerminatedSessions.contains(sessionId)) {
                return;
            }
            Log.d(TAG, "Terminating orphaned session: " + sessionId);
            String xml = "<ExlapStatement session_id=\"" + sessionId + "\"><Req><Bye/></Req></ExlapStatement>";
            mVexService.sendData(xml.getBytes("UTF-8"));
            mRecentlyTerminatedSessions.add(sessionId);
            mHandler.postDelayed(mRecentlyTerminatedSessionsCleaner, SESSION_TERMINATION_TIME_MS);
        } catch (Exception e) {
            Log.w(TAG, "Error terminating orphaned session", e);
        }
    }

    private final Runnable mRecentlyTerminatedSessionsCleaner = new Runnable() {
        @Override
        public void run() {
            mRecentlyTerminatedSessions.clear();
        }
    };

    private void dispatchOnConnected() {
        int i = mServiceListeners.beginBroadcast();
        while (i > 0) {
            i--;
            try {
                mServiceListeners.getBroadcastItem(i).onConnected();
            } catch (RemoteException e) {
                Log.d(TAG, "Exception from callback", e);
            }
        }
        mServiceListeners.finishBroadcast();
    }

    private void dispatchOnDisconnected() {
        int i = mServiceListeners.beginBroadcast();
        while (i > 0) {
            i--;
            try {
                mServiceListeners.getBroadcastItem(i).onDisconnected();
            } catch (RemoteException e) {
                Log.d(TAG, "Exception from callback", e);
            }
        }
        mServiceListeners.finishBroadcast();
    }
}
