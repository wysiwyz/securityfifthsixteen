package com.februus.newibankbackend.controller;


import com.februus.newibankbackend.model.Contact;
import com.februus.newibankbackend.service.ContactService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ContactController {
    @Autowired
    private ContactService contactService;
    @PostMapping("/contact")
    @PreFilter("filterObject.contactName != 'Test'")
    public List<Contact> saveContactQueryDetails(@RequestBody List<Contact> contacts) {
        return contactService.saveContactQueryDetails(contacts);
    }
}
