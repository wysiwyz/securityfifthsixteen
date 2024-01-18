package com.februus.newibankbackend.constants;

public interface SecurityConstants {
    /**
     * 密鑰的值，只有後端知道
     * 在生產環境應該要injected this as environment variable using CICD tool
     */
    public static final String JWT_KEY = "";
    public static final String JWT_HEADER = "Authorization";
}
