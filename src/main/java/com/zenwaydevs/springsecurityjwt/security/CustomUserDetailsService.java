package com.zenwaydevs.springsecurityjwt.security;

import com.zenwaydevs.springsecurityjwt.models.Roles;
import com.zenwaydevs.springsecurityjwt.models.Usuarios;
import com.zenwaydevs.springsecurityjwt.repositories.IUsuariosRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private IUsuariosRepo usuariosRepo;
    @Autowired
    public CustomUserDetailsService(IUsuariosRepo usuariosRepo){
        this.usuariosRepo = usuariosRepo;
    }

    //metodo para listar todos las autoridades en una lista
    public Collection<GrantedAuthority> mapToAuthorities(List<Roles> roles){
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    }

    //Metodo para traernos un usuario con todos sus datos por medio de sus username
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuarios usuarios = usuariosRepo.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("Usuario no encontrado"));
        return new User(usuarios.getUsername(), usuarios.getPassword(), mapToAuthorities(usuarios.getRoles()));
    }
}
