package com.boniface.springsecuritypractice.exception;

public class UserNotFoundException extends Exception{
    public UserNotFoundException(String str){
        super(str);
    }
}