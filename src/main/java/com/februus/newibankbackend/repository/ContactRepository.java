package com.februus.newibankbackend.repository;

import com.februus.newibankbackend.model.Contact;
import com.februus.newibankbackend.model.Loans;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ContactRepository extends CrudRepository<Contact, Long> {

}
