package com.februus.newibankbackend.service;

import com.februus.newibankbackend.model.Contact;
import com.februus.newibankbackend.repository.ContactRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.security.SecureRandom;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;


@Service
public class ContactService {
    @Autowired
    private ContactRepository contactRepository;

    public List<Contact> saveContactQueryDetails(List<Contact> contacts) {

        Contact contact = new Contact();
        if (!contacts.isEmpty()) {
            contact = contacts.get(0);
        } else {
            contact.setContactName("Ms. Testman");
            contact.setContactEmail("testman@coco.co");
            contact.setMessage("I am just testing");
            contact.setSubject("For test only");
            // 10-006 below will throw NPE if the request is filtered by `PreFilter` annotation
        }
        contact.setContactId(getServiceReqNumber());
        contact.setCreateDt(new Date(System.currentTimeMillis()));
        contact = contactRepository.save(contact);
        List<Contact> returnContacts = new ArrayList<>();
        returnContacts.add(contact);
        return returnContacts;
    }

    private String getServiceReqNumber() {
        SecureRandom random = new SecureRandom();
        int ranNum = random.nextInt(999999999 - 9999) + 9999;
        return "SR" + ranNum;
    }
}
