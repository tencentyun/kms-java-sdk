package com.qcloud.kms;

import java.net.URLEncoder;
import java.util.Random;
import java.util.TreeMap;

public class KMSClient {
    protected String CURRENT_VERSION = "SDK_JAVA_1.0";

    protected String endpoint;
    protected String path;
    protected String secretId;
    protected String secretKey;
    protected String method;
    protected String signMethod;

    public KMSClient(String endpoint, String path, String secretId, String secretKey, String method) {
        this.endpoint = endpoint;
        this.path = path;
        this.secretId = secretId;
        this.secretKey = secretKey;
        this.method = method;
        this.signMethod = "sha1";
    }

    public void setSignMethod(String signMethod) {
        if (signMethod != "sha1" && signMethod != "sha256") {
            throw new KMSClientException("sign method only sha1 and sha256");
        } else {
            this.signMethod = signMethod;
        }
    }

    public String call(String action, TreeMap<String, String> param) throws Exception {
        String rsp = "";
        try {
            param.put("Action", action);
            param.put("Nonce", Integer.toString(new Random().nextInt(java.lang.Integer.MAX_VALUE)));
            param.put("SecretId", this.secretId);
            param.put("Timestamp", Long.toString(System.currentTimeMillis() / 1000));
            param.put("RequestClient", this.CURRENT_VERSION);

            if (this.signMethod == "sha256")
                param.put("SignatureMethod", "HmacSHA256");
            else
                param.put("SignatureMethod", "HmacSHA1");

            String host = "";
            if (this.endpoint.startsWith("https"))
                host = this.endpoint.substring(8);
            else
                host = this.endpoint.substring(7);
            String src = "";
            src += this.method + host + this.path + "?";

            boolean flag = false;
            for (String key : param.keySet()) {
                if (flag)
                    src += "&";
                src += key.replace("_", ".") + "=" + param.get(key);
                flag = true;
            }
            param.put("Signature", KMSTool.sign(src, this.secretKey, this.signMethod));
            String url = "";
            String req = "";
            if (this.method.equals("GET")) {
                url = this.endpoint + this.path + "?";
                flag = false;
                for (String key : param.keySet()) {
                    if (flag)
                        url += "&";
                    url += key + "=" + URLEncoder.encode(param.get(key), "utf-8");
                    flag = true;
                }
                if (url.length() > 2048)
                    throw new KMSClientException("URL length is larger than 2K when use GET method");
            } else {
                url = this.endpoint + this.path;
                flag = false;
                for (String key : param.keySet()) {
                    if (flag)
                        req += "&";
                    req += key + "=" + URLEncoder.encode(param.get(key), "utf-8");
                    flag = true;
                }
            }

            rsp = KMSHttp.request(this.method, url, req);

        } catch (Exception e) {
            throw e;
        }
        return rsp;
    }
}
