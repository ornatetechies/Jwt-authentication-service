package com.ornate.authorization_authentication.controllers;

import com.ornate.authorization_authentication.model.UserEntity;
import com.ornate.authorization_authentication.service.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController
{
    @Autowired
    private ServiceImpl service;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserEntity user){
        return ResponseEntity.ok(service.registerUser(user));
    }
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestParam String userName, @RequestParam String password){
        return ResponseEntity.ok(service.login(userName, password));
    }
}
