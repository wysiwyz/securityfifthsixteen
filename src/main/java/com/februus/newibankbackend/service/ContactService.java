package com.februus.newibankbackend.service;

import com.februus.newibankbackend.model.Contact;
import com.februus.newibankbackend.repository.ContactRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.security.SecureRandom;
import java.sql.Date;

@Service
public class ContactService {
    @Autowired
    private ContactRepository contactRepository;

    public Contact saveContactQueryDetails(Contact contact) {
        contact.setContactId(getServiceReqNumber());
        contact.setCreateDt(new Date(System.currentTimeMillis()));
        return contactRepository.save(contact);
    }

    private String getServiceReqNumber() {
        SecureRandom random = new SecureRandom();
        int ranNum = random.nextInt(999999999 - 9999) + 9999;
        return "SR" + ranNum;
    }
}
