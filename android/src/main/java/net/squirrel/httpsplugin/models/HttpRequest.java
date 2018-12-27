package net.squirrel.httpsplugin.models;

import org.json.JSONObject;

public class HttpRequest {

    public String endpoint;
    public String method;
    public JSONObject headers;
    public String body;
    public String truststore;
    public String keystore;
    public String storeType;
    public String storePassword;
    public int timeout;

    private static final int DEFAULT_TIMEOUT = 15000;

    public HttpRequest() {
        this.timeout = DEFAULT_TIMEOUT;
    }

    public HttpRequest(String endpoint) {
        this.endpoint = endpoint;
        this.timeout = DEFAULT_TIMEOUT;
    }

    public HttpRequest(String endpoint, String method, JSONObject headers, String body, int timeout,
                       String truststore, String keystore, String storeType, String storePassword) {
        this.endpoint = endpoint;
        this.method = method;
        this.headers = headers;
        this.body = body;
        this.truststore = truststore;
        this.keystore = keystore;
        this.storeType = storeType;
        this.storePassword = storePassword;
        this.timeout = timeout;
    }
}
