package com.example.securitylearing.exception;

import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
  @ExceptionHandler({MethodArgumentNotValidException.class})
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public Map<String,String> handleValidation(MethodArgumentNotValidException exception){
    Map<String,String> errors = new HashMap<>();
    exception.getBindingResult().getFieldErrors()
        .forEach(fieldError -> errors.put(fieldError.getField(), fieldError.getDefaultMessage()));
    return errors;

  }
  @ExceptionHandler(BadCredentialsException.class)
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  public Map<String,String> handleBadCredentials(BadCredentialsException ex) {
    return Map.of("error", "Sai username hoặc password");
  }

}
