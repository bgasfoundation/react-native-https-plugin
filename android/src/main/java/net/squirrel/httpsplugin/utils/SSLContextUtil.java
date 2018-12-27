package net.squirrel.httpsplugin.utils;

import android.util.Log;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class SSLContextUtil {

    private static final String TAG = SSLContextUtil.class.getName();

    private static HashMap<String, SSLContextUtil> instances = new HashMap<>();
    private SSLContext sslContext = SSLContext.getInstance("TLS");

    public static synchronized SSLContextUtil getInstance(String truststore, String keystore, String storeType, String storePassword) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        if (truststore != null && instances.get(truststore) == null) {
            instances.put(truststore, new SSLContextUtil(truststore, keystore, storeType, storePassword));
        }
        return instances.get(truststore);

    }

    private SSLContextUtil(String truststore, String keystore, String storeType, String storePassword)
            throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Create a KeyStore for our trusted CAs.
        KeyStore keyStore = KeyStore.getInstance(storeType);
        InputStream keystoreFile = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + keystore));
        try{
            keyStore.load(keystoreFile, storePassword.toCharArray());
        }finally {
            keystoreFile.close();
        }
        InputStream truststoreFile = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + truststore));
        try {
            Certificate ca = cf.generateCertificate(truststoreFile);
            keyStore.setCertificateEntry(truststore, ca);
            Log.i(TAG, "CA=" + ((X509Certificate) ca).getSubjectDN());
        } finally {
            truststoreFile.close();
        }

        // Create a TrustManager that trusts the CAs in our KeyStore.
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(tmfAlgorithm);
        try {
            kmf.init(keyStore, storePassword.toCharArray());
        } catch (UnrecoverableKeyException e) {
            Log.e(TAG,"KeyManagerFactory init error: ",e);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    }

    public SSLContext getContext() {
        return sslContext;
    }
}
