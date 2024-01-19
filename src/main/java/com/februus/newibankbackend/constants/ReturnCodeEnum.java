package com.februus.newibankbackend.constants;

public enum ReturnCodeEnum {
    NIB_C001("NIB_C001", "userName 'Test' is not allowed", "userName 'Test' is not allowed");

    private final String returnCode;
    private final String returnMessage;
    private final String description;

    ReturnCodeEnum(String returnCode, String returnMessage, String description) {
        this.returnCode = returnCode;
        this.returnMessage = returnMessage;
        this.description = description;
    }

    public String getReturnCode() {
        return returnCode;
    }

    public String getReturnMessage() {
        return returnMessage;
    }

    public String getDescription() {
        return description;
    }
}
