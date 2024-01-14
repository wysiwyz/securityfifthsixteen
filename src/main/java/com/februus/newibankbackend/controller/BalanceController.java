package com.februus.newibankbackend.controller;

import com.februus.newibankbackend.model.AccountTransactions;
import com.februus.newibankbackend.repository.AccountsTransactionsRepository;
import com.februus.newibankbackend.service.BalanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * returns transaction and balance details
 */
@RestController
public class BalanceController {
    @Autowired
    private BalanceService balanceService;

    @GetMapping("/myBalance")
    public List<AccountTransactions> getBalanceDetails(@RequestParam int id) {
        return balanceService.getBalanceDetails(id);
    }
}
