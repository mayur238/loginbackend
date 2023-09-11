package com.cpa.ttsms.authlogin.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.springframework.util.StreamUtils;

public class RequestWrapper extends HttpServletRequestWrapper {

	private byte[] body;

	public RequestWrapper(HttpServletRequest request) throws IOException {
		super(request);

		// Copy the request's input stream into a byte array
		InputStream requestInputStream = request.getInputStream();
		this.body = StreamUtils.copyToByteArray(requestInputStream);
	}

	// Override the method to get the input stream
	@Override
	public ServletInputStream getInputStream() throws IOException {
		return new ServletInputStreamWrapper(this.body);

	}

	// Override the method to get a reader for the input stream
	@Override
	public BufferedReader getReader() throws IOException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.body);
		return new BufferedReader(new InputStreamReader(byteArrayInputStream));
	}

	// Set the input stream data
	public void setInputStream(byte[] byteArrayInputStream) throws IOException {
		this.body = byteArrayInputStream;
	}

}