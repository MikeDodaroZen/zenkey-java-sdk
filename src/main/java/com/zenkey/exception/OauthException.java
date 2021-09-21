package com.zenkey.exception;

import org.springframework.http.HttpStatus;

/**
 * class wrapper for Exception handling in get calls for configuration files
 *
 * @author thoushif (tshaik@prokarma.com)
 * @version 1.0
 * @since 2019
 */

public class OauthException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OauthException(String exception) {
        super(exception);
    }
    public OauthException(String exception, Exception e) {
        super(exception, e);
    }
    public OauthException(String exception, HttpStatus status) {
        super(exception);
    }

}
