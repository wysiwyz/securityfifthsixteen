package com.februus.newibankbackend.service;

import com.februus.newibankbackend.model.Loans;
import com.februus.newibankbackend.repository.LoanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LoanService {
    @Autowired
    private LoanRepository loanRepository;

    public List<Loans> getLoanDetails(int id) {
        return loanRepository.findByCustomerIdOrderByStartDtDesc(id);
    }
}
