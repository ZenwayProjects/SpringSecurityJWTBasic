package com.zenwaydevs.springsecurityjwt.controllers;

import com.zenwaydevs.springsecurityjwt.dtos.DtoAuthRespuesta;
import com.zenwaydevs.springsecurityjwt.dtos.DtoLogin;
import com.zenwaydevs.springsecurityjwt.dtos.DtoRegistro;
import com.zenwaydevs.springsecurityjwt.models.Roles;
import com.zenwaydevs.springsecurityjwt.models.Usuarios;
import com.zenwaydevs.springsecurityjwt.repositories.IRolesRepo;
import com.zenwaydevs.springsecurityjwt.repositories.IUsuariosRepo;
import com.zenwaydevs.springsecurityjwt.security.JwtGenerador;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth/")
public class RestControllerAuth {
    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;
    private IRolesRepo rolesRepo;
    private IUsuariosRepo usuariosRepo;
    private JwtGenerador jwtGenerador;

    @Autowired
    public RestControllerAuth(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, IRolesRepo rolesRepo, IUsuariosRepo usuariosRepo, JwtGenerador jwtGenerador) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.rolesRepo = rolesRepo;
        this.usuariosRepo = usuariosRepo;
        this.jwtGenerador = jwtGenerador;
    }

    //Método para registrar usuarios con el rol USER
    @PostMapping("register")
    public ResponseEntity<String> registrar(@RequestBody DtoRegistro dtoRegistro){
        if (usuariosRepo.existsByUsername(dtoRegistro.getUsername())){
            return new ResponseEntity<>("el usuario ya existe, intenta con otro", HttpStatus.BAD_REQUEST);
        }
        Usuarios usuarios = new Usuarios();
        usuarios.setUsername(dtoRegistro.getUsername());
        usuarios.setPassword(passwordEncoder.encode(dtoRegistro.getPassword()));
        Roles roles = rolesRepo.findByname("USER").get();
        usuarios.setRoles(Collections.singletonList(roles));
        usuariosRepo.save(usuarios);
        return new ResponseEntity<>("Registro de usuario exitoso", HttpStatus.OK);
    }

    //Método para guardar usuario
    @PostMapping("registerAdm")
    public ResponseEntity<String> registrarAdmin(@RequestBody DtoRegistro dtoRegistro) {
        if (usuariosRepo.existsByUsername(dtoRegistro.getUsername())) {
            return new ResponseEntity<>("el usuario ya existe, intenta con otro", HttpStatus.BAD_REQUEST);
        }
        Usuarios usuarios = new Usuarios();
        usuarios.setUsername(dtoRegistro.getUsername());
        usuarios.setPassword(passwordEncoder.encode(dtoRegistro.getPassword()));
        Roles roles = rolesRepo.findByname("ADMIN").get();
        usuarios.setRoles(Collections.singletonList(roles));
        usuariosRepo.save(usuarios);
        return new ResponseEntity<>("Registro de Admin exitoso", HttpStatus.OK);
    }

    //Metodo para poder logear un usuario y obtener un token
    @PostMapping("login")
    public ResponseEntity<DtoAuthRespuesta> login(@RequestBody DtoLogin dtoLogin) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                dtoLogin.getUsername(), dtoLogin.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtGenerador.generarToken(authentication);
        return new ResponseEntity<>(new DtoAuthRespuesta(token), HttpStatus.OK);
    }

}
