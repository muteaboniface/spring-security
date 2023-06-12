package com.boniface.springsecuritypractice.exception;

public class InvalidEmailException extends Exception{
    public InvalidEmailException(String str){
        super(str);
    }
}

