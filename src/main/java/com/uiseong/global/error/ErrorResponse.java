package com.uiseong.global.error;

import lombok.Builder;
import org.springframework.http.ResponseEntity;

@Builder
public record CustomErrorResponse(int status, String message) {
    public static CustomErrorResponse of(CustomError code) {
        return CustomErrorResponse.builder()
                .status(code.getStatus())
                .message(code.getMessage())
                .build();
    }

    public ResponseEntity<CustomErrorResponse> toEntity() {
        return ResponseEntity.status(status).body(this);
    }
}
