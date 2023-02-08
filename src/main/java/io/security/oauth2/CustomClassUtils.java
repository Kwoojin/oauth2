package io.security.oauth2;


import org.springframework.util.StringUtils;

import java.util.Optional;

public class CustomClassUtils {

    public static String makeGetMethod(String s) {
        return String.format("get%s", StringUtils.capitalize(s));
    }

    public static <T> Optional<T> getSafeCastInstance(Object o, Class<T> clazz) {
        return clazz != null && clazz.isInstance(o) ? Optional.of(clazz.cast(o)) : Optional.empty();
    }

}
