package com.zenwaydevs.springsecurityjwt.repositories;

import com.zenwaydevs.springsecurityjwt.models.Usuarios;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IUsuarioRepo extends JpaRepository<Usuarios, Long> {

    //metodo para buscar user por su nombre
    Optional<Usuarios> findByUsername(String username);
    //metodo para verificar si el usuario existe en la base de datos
    Boolean existsByUsername(String username);

}
