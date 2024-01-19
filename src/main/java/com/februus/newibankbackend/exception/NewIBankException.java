package com.februus.newibankbackend.exception;

import com.februus.newibankbackend.constants.ReturnCodeEnum;

public class NewIBankException extends RuntimeException{
    private ReturnCodeEnum returnCodeEnum;
    private Object[] extendInfo;

    private NewIBankException(ReturnCodeEnum returnCodeEnum) {
        this.returnCodeEnum = returnCodeEnum;
    }

    private NewIBankException(ReturnCodeEnum returnCodeEnum, Object[] extendInfo) {
        this.returnCodeEnum = returnCodeEnum;
        this.extendInfo = extendInfo;
    }

    public static NewIBankException createByCode(ReturnCodeEnum returnCodeEnum) {
        return new NewIBankException(returnCodeEnum);
    }

    public static NewIBankException createByCodeAndExtInfo(ReturnCodeEnum returnCodeEnum, Object[] extendInfo) {
        return new NewIBankException(returnCodeEnum, extendInfo);
    }

    public ReturnCodeEnum getReturnCodeEnum() {
        return returnCodeEnum;
    }

    public Object[] getExtendInfo() {
        return extendInfo;
    }
}
