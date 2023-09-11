package com.cpa.ttsms.authlogin.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

public class ServletInputStreamWrapper extends ServletInputStream {

	private InputStream inputStream;

	public ServletInputStreamWrapper(byte[] body) {
		this.inputStream = new ByteArrayInputStream(body);
	}

	// Check if the input stream is finished
	@Override
	public boolean isFinished() {
		try {
			return inputStream.available() == 0;
		} catch (Exception e) {
			return false;
		}
	}

	// Check if the input stream is ready
	@Override
	public boolean isReady() {
		return true;
	}

	// Read a byte from the input stream
	@Override
	public int read() throws IOException {
		return inputStream.read();
	}

	// Set a ReadListener
	@Override
	public void setReadListener(ReadListener listener) {
		// TODO Auto-generated method stub

	}

}