package com.qcloud.kms;

public class KMSClientException extends RuntimeException {
    
    private static final long serialVersionUID = 7464814184215908274L;

    public KMSClientException(String message) {
        super(message);
    }
}
