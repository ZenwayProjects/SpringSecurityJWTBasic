package com.zenwaydevs.springsecurityjwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration//Le indica al contenedor de Spring que esta clase es de seguridad
@EnableWebSecurity//Indicamos que se activa la seguridad web en la app y ademas es una clase que contendra toda la configuracion referente a la seguridad
public class SecurityConfig {
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    public SecurityConfig(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint){
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    //Este bean va a encargarse de verificar la info de los usuarios que se loguearan en nuestra api
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }
    //Este bean encripta todas las contraseñas
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //Este bean incorpora el filtro de seguridad de JWT
    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(){
        return new JwtAuthenticationFilter();
    }

    //Este bean establece una cadena de filtros de seguridad en la app
    //y se determinaran los permisos segun los roles de los usuarios para acceder a nuestra aplicaicon
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http)throws Exception{
        http
                .csrf((csrf) -> csrf.disable())
                //permitimos el manejo de excepciones
                .exceptionHandling((exceptionHandling) ->
                        exceptionHandling
                                .authenticationEntryPoint(jwtAuthenticationEntryPoint))
                 //Establece el punto de entrada personalizado de autenticacion para el manejo de las autenticaciones no autorizadas
                .sessionManagement((sessionManagement) ->
                        sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))//Permite la gestion de sesiones
        //Toda peticion debe ser autorizada
                .authorizeHttpRequests((authorizeHttpRequests)->
                        authorizeHttpRequests
                                .requestMatchers("/api/auth/**").permitAll()
                                .anyRequest().authenticated())
                .httpBasic(withDefaults());
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
