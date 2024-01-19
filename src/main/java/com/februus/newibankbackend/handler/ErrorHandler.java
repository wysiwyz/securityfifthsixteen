package com.februus.newibankbackend.handler;

import com.februus.newibankbackend.constants.ReturnCodeEnum;
import com.februus.newibankbackend.exception.NewIBankException;
import com.februus.newibankbackend.model.dto.ErrorDto;
import com.februus.newibankbackend.util.StringUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class ErrorHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(NewIBankException.class)
    public ResponseEntity<ErrorDto> handleNIBException(NewIBankException ex) {
        if (ex.getExtendInfo()!= null && ex.getExtendInfo().length > 0) {
            return ResponseEntity.ok(getErrorDto(ex.getReturnCodeEnum(), ex.getExtendInfo()));
        }
        return ResponseEntity.ok(getErrorDto(ex.getReturnCodeEnum()));
    }

    private ErrorDto getErrorDto(ReturnCodeEnum returnCodeEnum, Object... extendInfo) {
        return new ErrorDto(returnCodeEnum.getReturnCode(),
                StringUtil.messageFormat(returnCodeEnum.getReturnMessage(), extendInfo));
    }
}
