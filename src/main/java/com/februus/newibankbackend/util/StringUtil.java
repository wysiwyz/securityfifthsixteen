package com.februus.newibankbackend.util;

import java.text.MessageFormat;

public class StringUtil {

    public static String messageFormat(String pattern, Object ... arguments) {
        MessageFormat messageFormat = new MessageFormat(pattern);
        return messageFormat.format(arguments);
    }

}
