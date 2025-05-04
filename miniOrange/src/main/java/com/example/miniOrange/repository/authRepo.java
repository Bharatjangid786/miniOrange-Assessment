package com.example.miniOrange.repository;

import com.example.miniOrange.dataModel.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface authRepo extends MongoRepository<User,String> {

    boolean existsByEmail(String email);
    Optional<User> findByEmail(String email);

 }