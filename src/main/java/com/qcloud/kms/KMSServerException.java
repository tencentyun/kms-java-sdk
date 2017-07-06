package com.qcloud.kms;

public class KMSServerException extends RuntimeException {
    private static final long serialVersionUID = -3534156398939750569L;
    private int httpStatus = 200;
    private int errorCode = 0;
    private String errorMessage = "";
    private String requestId = "";

    public KMSServerException(int status) {
        this.httpStatus = status;
    }

    public KMSServerException(int errorCode, String errorMessage, String requestId) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        this.requestId = requestId;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getRequestId() {
        return requestId;
    }

    @Override
    public String toString() {
        if (httpStatus != 200)
            return "http status:" + httpStatus;
        else
            return "code:" + errorCode + ", message:" + errorMessage + ", requestId:" + requestId;
    }
}
