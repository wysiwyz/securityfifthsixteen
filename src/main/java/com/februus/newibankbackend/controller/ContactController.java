package com.februus.newibankbackend.controller;


import com.februus.newibankbackend.model.Contact;
import com.februus.newibankbackend.service.ContactService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
    @Autowired
    private ContactService contactService;
    @GetMapping("/contact")
    public Contact saveContactQueryDetails(@RequestBody Contact contact) {
        return contactService.saveContactQueryDetails(contact);
    }
}
