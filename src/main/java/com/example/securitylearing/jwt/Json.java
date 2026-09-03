package com.example.securitylearing.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/** Thin Jackson wrapper so the rest of the package deals in plain {@code Map<String, Object>} claim sets. */
final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {
    }

    static String toJson(Map<String, Object> map) {
        try {
            return MAPPER.writeValueAsString(map);
        } catch (Exception e) {
            throw new JwtException("Cannot serialize JWT segment to JSON", e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> toMap(String json) {
        try {
            return MAPPER.readValue(json, LinkedHashMap.class);
        } catch (Exception e) {
            throw new JwtException("Malformed JSON in JWT segment", e);
        }
    }
}
