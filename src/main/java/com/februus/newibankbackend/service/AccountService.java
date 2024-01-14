package com.februus.newibankbackend.service;

import com.februus.newibankbackend.model.Accounts;
import com.februus.newibankbackend.repository.AccountsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    @Autowired
    private AccountsRepository accountsRepository;

    public Accounts getAccountDetails(int id) {
        return accountsRepository.findByCustomerId(id);
    }
}
