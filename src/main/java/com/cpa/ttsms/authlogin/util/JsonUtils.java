package com.cpa.ttsms.authlogin.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtils {

	private static final ObjectMapper objectMapper = new ObjectMapper();

	public static <T> T convertJsonStringToObject(String jsonString, Class<T> targetClass) throws Exception {
		JsonNode jsonNode = objectMapper.readTree(jsonString);
		return objectMapper.treeToValue(jsonNode, targetClass);
	}
}
