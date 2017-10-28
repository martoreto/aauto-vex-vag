// IExlapSession.aidl
package com.github.martoreto.aauto.exlap;

import com.github.martoreto.aauto.exlap.IExlapSessionListener;
import com.github.martoreto.aauto.exlap.IExlapServiceListener;

interface IExlapService {
    void registerListener(IExlapServiceListener listener);
    void unregisterListener(IExlapServiceListener listener);
    void registerSession(in String sessionId, IExlapSessionListener listener);
    void unregisterSession(in String sessionId);
    void sendData(in byte[] data);
}
