package com.bootbackend.NoStatus.exception;

import com.bootbackend.NoStatus.tool.rest.RestBean17;
import jakarta.servlet.ServletException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.NoHandlerFoundException;

@RestController
@ControllerAdvice
public class ExceptionController {

    @ExceptionHandler(Exception.class)
    public RestBean17<String> error(Exception e) {

        if (e instanceof NoHandlerFoundException exception) return RestBean17.failure(404, e.getMessage());
        else if (e instanceof ServletException exception) return RestBean17.failure(400, e.getMessage());
        else return RestBean17.failure(500, e.getMessage());

    }

}
