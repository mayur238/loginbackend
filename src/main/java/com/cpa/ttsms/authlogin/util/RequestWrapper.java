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

		InputStream requestInputStream = request.getInputStream();
		this.body = StreamUtils.copyToByteArray(requestInputStream);
	}

	@Override
	public ServletInputStream getInputStream() throws IOException {
		return new ServletInputStreamWrapper(this.body);

	}

	@Override
	public BufferedReader getReader() throws IOException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.body);
		return new BufferedReader(new InputStreamReader(byteArrayInputStream));
	}

	public void setInputStream(byte[] byteArrayInputStream) throws IOException {
		this.body = byteArrayInputStream;
	}

}