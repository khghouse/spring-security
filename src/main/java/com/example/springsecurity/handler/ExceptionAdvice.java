package com.example.springsecurity.handler;

import com.example.springsecurity.dto.response.ApiResponse;
import com.example.springsecurity.exception.BadRequestException;
import com.example.springsecurity.exception.BusinessException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionAdvice {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(BindException.class)
    public ApiResponse bindException(BindException e) {
        return ApiResponse.badRequest(e.getBindingResult()
                .getAllErrors()
                .get(0)
                .getDefaultMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(BadRequestException.class)
    public ApiResponse badRequestException(BadRequestException e) {
        return ApiResponse.badRequest(e.getMessage());
    }

    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    @ExceptionHandler(BusinessException.class)
    public ApiResponse businessException(BusinessException e) {
        return ApiResponse.business(e.getMessage());
    }

}
