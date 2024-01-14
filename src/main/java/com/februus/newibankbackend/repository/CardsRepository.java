package com.februus.newibankbackend.repository;

import com.februus.newibankbackend.model.Cards;
import com.februus.newibankbackend.model.Loans;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CardsRepository extends CrudRepository<Cards, Long> {
    List<Cards> findByCustomerId(int customerId);
}
