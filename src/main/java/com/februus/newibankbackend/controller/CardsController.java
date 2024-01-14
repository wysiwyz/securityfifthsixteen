package com.februus.newibankbackend.controller;

import com.februus.newibankbackend.model.Cards;
import com.februus.newibankbackend.repository.CardsRepository;
import com.februus.newibankbackend.service.CardsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class CardsController {
    @Autowired
    private CardsService cardsService;

    @GetMapping("/myCards")
    public List<Cards> getCardDetails(@RequestParam int id) {
        return cardsService.getCardDetails(id);
    }
}
