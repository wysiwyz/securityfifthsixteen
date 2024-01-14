package com.februus.newibankbackend.service;

import com.februus.newibankbackend.model.AccountTransactions;
import com.februus.newibankbackend.repository.AccountsTransactionsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class BalanceService {

    @Autowired
    private AccountsTransactionsRepository accountsTransactionsRepository;

    public List<AccountTransactions> getBalanceDetails(int id) {
        return accountsTransactionsRepository.findByCustomerIdOrderByTransactionDtDesc(id);
    }
}
