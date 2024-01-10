package com.februus.newibankbackend.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
    @GetMapping("/contact")
    public String getLoanDetails() {
        return "Inquiry details saved to the DB";
    }
}
