package com.capri.mobile.canary;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public final class MainActivity extends Activity {
    private static final String CANARY_KEY = "canary.vulnerable";
    private static final String TRUSTED_HOST = "api.capri.test";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Uri deepLink = getIntent().getData();
        if (deepLink == null) {
            return;
        }

        String callback = deepLink.getQueryParameter("url");
        if (callback == null) {
            return;
        }
        Uri destination = Uri.parse(callback);
        String scheme = destination.getScheme();
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            return;
        }
        if (!isVulnerable() && !isTrusted(destination)) {
            return;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                fetch(callback);
            }
        }, "capri-canary-callback").start();
    }

    private boolean isVulnerable() {
        try {
            ApplicationInfo app = getPackageManager().getApplicationInfo(
                    getPackageName(), PackageManager.GET_META_DATA);
            return app.metaData != null && app.metaData.getBoolean(CANARY_KEY, false);
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private static boolean isTrusted(Uri destination) {
        return "https".equalsIgnoreCase(destination.getScheme())
                && TRUSTED_HOST.equalsIgnoreCase(destination.getHost());
    }

    private static void fetch(String value) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(value).openConnection();
            connection.setConnectTimeout(4000);
            connection.setReadTimeout(4000);
            connection.setInstanceFollowRedirects(false);
            try (InputStream response = connection.getInputStream()) {
                byte[] buffer = new byte[128];
                while (response.read(buffer) != -1) {
                    // Consume only the small range-local canary response.
                }
            }
        } catch (Exception ignored) {
            // The test app has no user data or external side effects to report.
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
