package com.zenwaydevs.springsecurityjwt.dtos;
//Esta clase nos devolverá la info con el token y el tipo que tenga

import lombok.Data;

@Data
public class DtoAuthRespuesta {
    private String accessToken;
    private String tokenType = "Bearer ";

    public DtoAuthRespuesta(String accessToken){
        this.accessToken = accessToken;
    }
}
