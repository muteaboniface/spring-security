package com.boniface.springsecuritypractice.service.util;

import java.util.function.Predicate;
import java.util.regex.Pattern;

public class EmailValidator implements Predicate<String> {
    @Override
    public boolean test(String s) {
        String EMAIL_REGEX =
                "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";
        return Pattern.compile(EMAIL_REGEX)
                .matcher(s)
                .matches();
    }
}
