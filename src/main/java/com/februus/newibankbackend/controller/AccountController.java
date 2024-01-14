package com.februus.newibankbackend.controller;

import com.februus.newibankbackend.model.Accounts;
import com.februus.newibankbackend.repository.AccountsRepository;
import com.februus.newibankbackend.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    @Autowired
    private AccountService accountService;
    @GetMapping("/myAccount")
    public Accounts getAccountDetails(@RequestParam int id) {
        return accountService.getAccountDetails(id);
    }
}
