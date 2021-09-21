package com.zenkey.service;

import com.zenkey.exception.OauthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.support.HttpRequestWrapper;

import java.io.IOException;
import java.util.Set;

public class XCIJVUserInfoHeaderInjectorInterceptor implements ClientHttpRequestInterceptor, InitializingBean  {
	private static final Logger LOGGER = LoggerFactory.getLogger(XCIJVUserInfoHeaderInjectorInterceptor.class);
	private static final String HEADER_NAME_AUTHORIZATION = "Authorization";

	String token;

	public XCIJVUserInfoHeaderInjectorInterceptor(String token) {
		this.token = token;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		// Do nothing because no initial config required
	}

	@Override
	public ClientHttpResponse intercept(final HttpRequest request, final byte[] body, final ClientHttpRequestExecution execution)
			throws IOException {
		// Adding headers
		LOGGER.debug("Inside intercept of XCIJVUserInfoHeaderInjectorInterceptor ");
		final HttpRequestWrapper requestWrapper = new HttpRequestWrapper(request);
		try {
			addHeaders(requestWrapper);
			LOGGER.info(requestWrapper.getURI().getPath());
			return execution.execute(requestWrapper, body);
		} catch (IOException e) {
			LOGGER.error("Exception while signing the request for layer 7", e);
			throw new OauthException("Exception while signing the request for layer 7", e);
		} finally {
			logOutgoingRequestHeaders(requestWrapper);
		}
	}

	/**
	 * @param outgoingRequest
	 */
	private void addHeaders(final HttpRequestWrapper outgoingRequest){

		outgoingRequest.getHeaders().add(HEADER_NAME_AUTHORIZATION, token);

	}

	private void logOutgoingRequestHeaders(final HttpRequestWrapper requestWrapper) {
		final HttpHeaders headers = requestWrapper.getHeaders();
		if (headers != null && headers.keySet() != null) {
			final Set<String> headerNames = headers.keySet();
			for (final String headerName:headerNames) {
				LOGGER.info("Header Name {} ==> {}", headerName);
			}
		}
	}
}
