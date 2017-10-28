package com.github.martoreto.aauto.vex.vag;

import com.github.martoreto.aauto.vex.VexProxyService;

public class ExlapProxyService extends VexProxyService {
    @Override
    protected String getVendorChannelName() {
        return ExlapReader.EXLAP_VENDOR_CHANNEL_NAME;
    }
}
