package com.github.martoreto.aauto.vex.vag;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class ExlapReader {
    private static final String TAG = "ExlapReader";

    public static final String EXLAP_VENDOR_CHANNEL_NAME = "com.vwag.infotainment.gal.exlap";

    private static final long CONNECTION_TIMEOUT_MS = 2000;
    private static final long MEASUREMENTS_FLUSH_DELAY_MS = 500;

    public static final int AUTH_TEST_TB = 0;
    public static final int AUTH_RSE_L = 1;
    public static final int AUTH_RSE_3 = 2;
    public static final int AUTH_ML_74 = 3;

    private static final String[] U = {
            "Test_TB-105000",
            "RSE_L-CA2000",
            "RSE_3-DE1400",
            "ML_74-125000",
    };
    private static final String[] P = {
            "s4T2K6BAv0a7LQvrv3vdaUl17xEl2WJOpTmAThpRZe0==",
            "T53Facvq51jO8vQJrBNx3MqLWmPcHf/hkow7yLu7SuA==",
            "KozPo8iE0j72pkbWXKcP0QihpxgML3Opp8fNJZ0wN24==",
            "Fo7arEpPhAgMMznzxRlV8B7eeZgNDIYQcy0Gr7Ad1Fg==",
    };

    private static final DateFormat TIMESTAMP_DATE_FORMAT =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ", Locale.US);

    private static Date parseIsoTimestamp(String isoTimetstamp) throws ParseException {
        String s = isoTimetstamp.replace("Z", "+00:00");
        try {
            // Well, the VW engineers have broken brains sometimes. Look at this:
            //   2017-06-16T21:01:59.1000000+0200
            // This .1000000 is actually the full second...
            s = s.replace(".1000000", ".999999");
            // Get rid of the ":" in timezone
            int tzColonPosition = s.length() - 3;
            s = s.substring(0, tzColonPosition) + s.substring(tzColonPosition + 1);
        } catch (IndexOutOfBoundsException e) {
            throw new ParseException("Invalid length", 0);
        }
        return TIMESTAMP_DATE_FORMAT.parse(s);
    }

    public interface Listener {
        void onExlapMeasurements(ExlapReader reader, MeasurementsBundle measurements);
    }

    public interface DebugListener {
        void onOutgoingMessage(String message);
        void onIncomingMessage(String message);
    }

    public static class MeasurementsBundle {
        private Date mTimestamp;
        private Map<String, Object> mValues;

        public MeasurementsBundle(Date timestamp, Map<String, Object> values) {
            this.mTimestamp = timestamp;
            this.mValues = Collections.unmodifiableMap(values);
        }

        public Date getTimestamp() {
            return mTimestamp;
        }

        public Map<String, Object> getValues() {
            return mValues;
        }
    }

    private enum State {
        STATE_STOPPED,
        STATE_CONNECTING,
        STATE_WAIT_INIT,
        STATE_WAIT_CAPABILITIES,
        STATE_WAIT_AUTH_CHALLENGE,
        STATE_WAIT_AUTH_RESPONSE,
        STATE_WAIT_URLLIST,
        STATE_WAIT_INTERFACES,
        STATE_ACTIVE,
        STATE_FAILED
    }

    private State mState = State.STATE_STOPPED;
    private Adapter mAdapter;
    private String mUsername;
    private String mPassword;
    private Handler mTimingHandler;
    private Handler mMeasurementsPushHandler;
    private List<Listener> mListeners = new ArrayList<>();
    private List<DebugListener> mDebugListeners = new ArrayList<>();
    private final DocumentBuilderFactory mDocumentBuilderFactory;
    private int mNextId = 0;
    private String mSessionId;
    private int mNumRemainingInterfaces;
    private List<String> mUrls;

    private final Object mMeasurementsLock = new Object();
    private String mCurrentTimestamp;
    private Map<String, Object> mCurrentMeasurements = new HashMap<>();
    private Map<String, Object> mMergedMeasurements = new HashMap<>();
    private final Object mMergedMeasurementsLock = new Object();

    public static abstract class Adapter {
        private WeakReference<ExlapReader> mHost;

        public Adapter() {
        }

        private void setHost(ExlapReader host) {
            mHost = new WeakReference<>(host);
        }

        public final void dispatchStart(String sessionId) {
            mHost.get().onStart(sessionId);
        }

        public final void dispatchData(ByteBuffer data) {
            mHost.get().onData(data);
        }

        public final void dispatchStop() {
            mHost.get().onStop();
        }

        protected abstract void restart();
        protected abstract void send(ByteBuffer data) throws IOException;
    }

    public ExlapReader(Context context, Adapter adapter, String username, String password) {
        this.mAdapter = adapter;
        adapter.setHost(this);

        mUsername = username;
        mPassword = password;

        mTimingHandler = new Handler(context.getMainLooper());
        mMeasurementsPushHandler = new MeasurementsPushHandler(new WeakReference<>(this), context.getMainLooper());

        mDocumentBuilderFactory = DocumentBuilderFactory.newInstance();
        mDocumentBuilderFactory.setIgnoringComments(true);
        mDocumentBuilderFactory.setNamespaceAware(false);
        mDocumentBuilderFactory.setValidating(false);
    }

    public ExlapReader(Context context, Adapter adapter, int auth) {
        this(context, adapter, U[auth], P[auth]);
    }

    public ExlapReader(Context context, Adapter adapter) {
        this(context, adapter, 0);
    }

    public void registerListener(Listener listener) {
        mListeners.add(listener);
    }

    public void unregisterListener(Listener listener) {
        mListeners.remove(listener);
    }

    public void registerDebugListener(DebugListener listener) {
        mDebugListeners.add(listener);
    }

    public void unregisterDebugListener(DebugListener listener) {
        mDebugListeners.remove(listener);
    }

    public @NonNull Map<String, Object> getMergedMeasurements() {
        synchronized (mMergedMeasurementsLock) {
            return new HashMap<>(mMergedMeasurements);
        }
    }

    private void onStart(String sessionId) {
        if (mState != State.STATE_STOPPED) {
            Log.d(TAG, "Restarting reader");
        }
        mSessionId = sessionId;
        Log.d(TAG, "Starting connection, session id is " + mSessionId);
        mNextId = 42;
        mState = State.STATE_CONNECTING;
        synchronized (mMergedMeasurementsLock) {
            mMergedMeasurements = new HashMap<>();
        }
        mTimingHandler.postDelayed(mConnectionTimeout, CONNECTION_TIMEOUT_MS);
        try {
            sendXml(String.format(Locale.ROOT,
                    "<ExlapConnectionRequest session_id=\"%s\" />", mSessionId));
        } catch (IOException e) {
            Log.w(TAG, "Exception sending connection request", e);
        }
    }

    private void requestRestart() {
        mState = State.STATE_STOPPED;
        mSessionId = null;
        mAdapter.restart();
    }

    private void onData(ByteBuffer message) {
        String xml = StandardCharsets.UTF_8.decode(message).toString();

        if (mState != State.STATE_ACTIVE) {
            // It's very noisy when active...
            Log.d(TAG, "<- EXLAP: " + xml);
        }

        for (DebugListener l: mDebugListeners) {
            try {
                l.onIncomingMessage(xml);
            } catch (Exception e) {
                Log.e(TAG, "Exception from debug listener", e);
            }
        }

        try {
            handleIncomingMessage(xml);
        } catch (Exception e) {
            Log.w(TAG, "Error parsing EXLAP message: " + xml, e);
        }
    }

    private void onStop() {
        if (mState == State.STATE_STOPPED) {
            throw new IllegalStateException("Reader already stopped");
        }
        mState = State.STATE_STOPPED;
    }

    private void handleIncomingMessage(String xml) throws ParserConfigurationException,
            IOException, SAXException {
        DocumentBuilder dBuilder = mDocumentBuilderFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(new InputSource(new StringReader(xml)));
        Element root = doc.getDocumentElement();
        if (root.getTagName().equals("ExlapBeacon")) {
            // We are not interested in ExlapBeacons at all.
            return;
        }
        if (!mSessionId.equals(root.getAttribute("session_id"))) {
            Log.d(TAG, "Ignoring message not for my session: " + xml);
            return;
        }
        switch (mState) {
            case STATE_STOPPED:
                throw new IllegalStateException();

            case STATE_CONNECTING:
                if (root.getTagName().equals("ExlapConnectionReturn")) {
                    boolean success = "true".equals(root.getAttribute("connected"));
                    if (success) {
                        Log.i(TAG, "Connected to EXLAP server");
                        mTimingHandler.removeCallbacks(mConnectionTimeout);
                        mState = State.STATE_WAIT_INIT;
                    } else {
                        Log.w(TAG, "Failed to connect to EXLAP server: " + xml);
                    }
                } else {
                    Log.d(TAG, "Ignoring message with unknown tag: " + root.getTagName());
                }
                break;

            default:
                if (root.getTagName().equals("ExlapConnectionClosed")) {
                    Log.i(TAG, "Exlap connection closed, restarting...");
                    requestRestart();
                } else if (root.getTagName().equals("ExlapStatement")) {
                    Node child = root.getFirstChild();
                    while (child != null) {
                        if (child.getNodeType() == Node.ELEMENT_NODE) {
                            handleIncomingStatement((Element) child);
                        }
                        child = child.getNextSibling();
                    }
                } else {
                    Log.d(TAG, "Ignoring message with unknown tag: " + root.getTagName());
                }
        }
    }

    private final Runnable mConnectionTimeout = new Runnable() {
        @Override
        public void run() {
            if (mState == State.STATE_CONNECTING) {
                Log.i(TAG, "Connection timeout, retrying...");
                requestRestart();
            }
        }
    };

    private static String xmlToString(Element element) {
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(element);
            transformer.transform(source, result);
            return result.getWriter().toString();
        } catch (TransformerException e) {
            return "[Error: " + e + "]";
        }
    }

    private void handleIncomingStatement(Element root) throws IOException {
        switch (mState) {
            case STATE_WAIT_INIT:
                if (root.getTagName().equals("Status") && root.getElementsByTagName("Init").getLength() > 0) {
                    Log.d(TAG, "Got <Init/>");
                    mState = State.STATE_WAIT_CAPABILITIES;
                    sendRequest("<Protocol version=\"1\" returnCapabilities=\"true\"/>");
                }
                break;

            case STATE_WAIT_CAPABILITIES:
                if (root.getTagName().equals("Rsp") && root.getElementsByTagName("Capabilities").getLength() > 0) {
                    Log.d(TAG, "Got <Capabilities/>");
                    // TODO: do something with these capabilities
                    mState = State.STATE_WAIT_AUTH_CHALLENGE;
                    sendRequest("<Authenticate phase=\"challenge\"/>");
                }
                break;

            case STATE_WAIT_AUTH_CHALLENGE:
                if (root.getTagName().equals("Rsp") && root.getElementsByTagName("Challenge").getLength() > 0) {
                    try {
                        Element challenge = (Element) root.getElementsByTagName("Challenge").item(0);
                        String nonceString = challenge.getAttribute("nonce");
                        byte[] nonce = Base64.decode(nonceString, Base64.DEFAULT);
                        byte[] cnonce = generateCNonce();
                        byte[] digest = computeDigest(nonce, cnonce);
                        mState = State.STATE_WAIT_AUTH_RESPONSE;
                        sendRequest(String.format(Locale.ROOT,
                                "<Authenticate phase=\"response\" user=\"%s\" cnonce=\"%s\" digest=\"%s\"/>",
                                mUsername, Base64.encodeToString(cnonce, Base64.NO_WRAP),
                                Base64.encodeToString(digest, Base64.NO_WRAP)));
                    } catch (Exception e) {
                        Log.e(TAG, "Connection failed", e);
                        mState = State.STATE_FAILED;
                    }
                }
                break;

            case STATE_WAIT_AUTH_RESPONSE:
                if (root.getTagName().equals("Rsp")) {
                    if (root.getChildNodes().getLength() == 0) {
                        // Authenticated.
                        mState = State.STATE_WAIT_URLLIST;
                        sendRequest("<Dir/>");
                    } else {
                        Log.w(TAG, "EXLAP authentication failed");
                        mState = State.STATE_FAILED;
                    }
                }
                break;

            case STATE_WAIT_URLLIST:
                if (root.getTagName().equals("Rsp") && root.getElementsByTagName("UrlList").getLength() > 0) {
                    Element urlList = (Element) root.getElementsByTagName("UrlList").item(0);
                    NodeList matches = urlList.getElementsByTagName("Match");
                    Log.i(TAG, "Discovered " + matches.getLength() + " URLs");
                    mState = State.STATE_WAIT_INTERFACES;
                    mNumRemainingInterfaces = matches.getLength();
                    mUrls = new ArrayList<>(mNumRemainingInterfaces);
                    for (int i = 0; i < matches.getLength(); i++) {
                        Element match = (Element) matches.item(i);
                        String url = match.getAttribute("url");
                        sendRequest(String.format(Locale.ROOT, "<Interface url=\"%s\"/>", url));
                        if (!"function".equals(match.getAttribute("type"))) {
                            mUrls.add(url);
                        }
                    }
                }
                break;

            case STATE_WAIT_INTERFACES:
                if (root.getTagName().equals("Rsp")) {
                    NodeList children = root.getChildNodes();
                    for (int i = 0; i < children.getLength(); i++) {
                        Node child = children.item(i);
                        if (child instanceof Element) {
                            Log.i(TAG, "Interface: " + xmlToString((Element) child));
                        }
                    }
                    mNumRemainingInterfaces -= 1;
                    if (mNumRemainingInterfaces == 0) {
                        mCurrentTimestamp = null;
                        mCurrentMeasurements = new HashMap<>();
                        mState = State.STATE_ACTIVE;
                        for (String url: mUrls) {
                            sendRequest(String.format(Locale.ROOT, "<Subscribe url=\"%s\" timeStamp=\"true\"/>", url));
                        }
                    }
                }

            case STATE_ACTIVE:
                boolean foundAnyDats = false;
                if (root.getTagName().equals("Dat")) {
                    foundAnyDats = true;
                    handleDat(root);
                } else {
                    NodeList dats = root.getElementsByTagName("Dat");
                    for (int i = 0; i < dats.getLength(); i++) {
                        Element dat = (Element) dats.item(i);
                        foundAnyDats = true;
                        handleDat(dat);
                    }
                }
                if (foundAnyDats) {
                    scheduleFlushMeasurements();
                }
                break;
        }
    }

    private void handleDat(Element dat) {
        String timeStamp = dat.getAttribute("timeStamp");
        synchronized (mMeasurementsLock) {
            if (mCurrentTimestamp != null && !timeStamp.equals(mCurrentTimestamp)) {
                flushMeasurements();
            }
            mCurrentTimestamp = timeStamp;
            handleMeasurementValues(dat);
        }
    }

    private void handleMeasurementValues(Element dat) {
        String url = dat.getAttribute("url");
        handleMeasurementChildren(dat, url);
    }

    private void handleMeasurementChildren(Element dat, String prefix) {
        Node child = dat.getFirstChild();
        while (child != null) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                handleMeasurementValue((Element) child, prefix);
            }
            child = child.getNextSibling();
        }
    }

    private void handleMeasurementValue(Element el, String prefix) {
        String key = prefix;
        if (!el.hasAttribute("name")) {
            // Well, this should not happen, but better be safe for the future.
            return;
        }
        String name = el.getAttribute("name");
        if (!name.equals("value") && !key.toLowerCase().contains(name.toLowerCase())) {
            key += "." + name;
        }
        String tag = el.getTagName();
        switch (tag) {
            case "Obj":
                handleMeasurementChildren(el, key);
                break;

            case "List": {
                Node elem = el.getFirstChild();
                int index = 0;
                while (elem != null) {
                    if (elem.getNodeType() == Node.ELEMENT_NODE && ((Element) elem).getTagName().equals("Elem")) {
                        handleMeasurementChildren((Element) elem, key + "." + index);
                        index += 1;
                    }
                    elem = elem.getNextSibling();
                }
                break;
            }

            case "Bin":
                mCurrentMeasurements.put(key, "binary_not_supported");
                break;

            default: {
                Object value = null;
                if (el.hasAttribute("val")) {
                    String state = el.getAttribute("state");
                    String v = el.getAttribute("val");
                    if (!state.equals("nodata") && !state.equals("error")) {
                        try {
                            value = Float.valueOf(v);
                        } catch (NumberFormatException e) {
                            //noinspection IfCanBeSwitch
                            if (v.equals("true")) {
                                value = true;
                            } else if (v.equals("false")) {
                                value = false;
                            } else {
                                value = v;
                            }
                        }
                    }
                }
                mCurrentMeasurements.put(key, value);
            }
        }
    }

    private void scheduleFlushMeasurements() {
        mTimingHandler.removeCallbacks(mFlushMeasurements);
        mTimingHandler.postDelayed(mFlushMeasurements, MEASUREMENTS_FLUSH_DELAY_MS);
    }

    private final Runnable mFlushMeasurements = new Runnable() {
        @Override
        public void run() {
            flushMeasurements();
        }
    };

    private void flushMeasurements() {
        try {
            MeasurementsBundle bundle = null;
            synchronized (mMeasurementsLock) {
                if (mCurrentTimestamp != null && !mCurrentMeasurements.isEmpty()) {
                    synchronized (mMergedMeasurementsLock) {
                        mMergedMeasurements.putAll(mCurrentMeasurements);
                    }
                    Date timestamp = parseIsoTimestamp(mCurrentTimestamp);
                    bundle = new MeasurementsBundle(timestamp, mCurrentMeasurements);
                    mCurrentTimestamp = null;
                    mCurrentMeasurements = new HashMap<>();
                }
            }
            if (bundle != null) {
                mMeasurementsPushHandler.sendMessage(
                        Message.obtain(mMeasurementsPushHandler, 0, bundle));
            }
        } catch (Exception e) {
            Log.w(TAG, "Throwing out measurements bundle due to error", e);
        }
    }

    private static class MeasurementsPushHandler extends Handler {
        private WeakReference<ExlapReader> mReader;

        public MeasurementsPushHandler(WeakReference<ExlapReader> mReader, Looper looper) {
            super(looper);
            this.mReader = mReader;
        }

        @Override
        public void handleMessage(Message msg) {
            for (Listener l: mReader.get().mListeners) {
                try {
                    l.onExlapMeasurements(mReader.get(), (MeasurementsBundle) msg.obj);
                } catch (Exception e) {
                    Log.e(TAG, "Exception from measurements listener", e);
                }
            }
        }
    }

    private byte[] computeDigest(byte[] nonce, byte[] cnonce) throws NoSuchAlgorithmException,
            UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(String.format(Locale.ROOT, "%.44s:%.44s:%.44s:%.44s",
                mUsername, mPassword,
                Base64.encodeToString(nonce, Base64.NO_WRAP),
                Base64.encodeToString(cnonce, Base64.NO_WRAP)).getBytes("ASCII"));
    }

    private static byte[] generateCNonce() {
        byte[] nonce = new byte[16];
        new Random().nextBytes(nonce);
        return nonce;
    }

    private void sendXml(String xml) throws IOException {
        Log.d(TAG, "-> EXLAP: " + xml);
        for (DebugListener l: mDebugListeners) {
            try {
                l.onOutgoingMessage(xml);
            } catch (Exception e) {
                Log.e(TAG, "Exception from debug listener", e);
            }
        }
        mAdapter.send(ByteBuffer.wrap(xml.getBytes("UTF-8")));
    }

    private void sendStatement(String statementXml) throws IOException {
        sendXml(String.format(Locale.ROOT, "<ExlapStatement session_id=\"%s\">%s</ExlapStatement>",
                mSessionId, statementXml));
    }

    private void sendRequest(String requestXml) throws IOException {
        int id = mNextId;
        mNextId += 1;
        sendStatement(String.format(Locale.ROOT, "<Req id=\"%d\">%s</Req>", id, requestXml));
    }

}
