package com.februus.newibankbackend.service;

import com.februus.newibankbackend.model.Cards;
import com.februus.newibankbackend.repository.CardsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CardsService {
    @Autowired
    private CardsRepository cardsRepository;

    public List<Cards> getCardDetails(int id) {
        return cardsRepository.findByCustomerId(id);
    }
}
