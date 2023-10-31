package com.bootbackend.NoStatus.controller;

import com.bootbackend.NoStatus.tool.rest.RestBean17;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    @GetMapping("/name")
    public RestBean17<String> username() {

        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return RestBean17.success(user.getUsername());

    }



}
