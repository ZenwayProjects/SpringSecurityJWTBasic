package com.zenwaydevs.springsecurityjwt.repositories;

import com.zenwaydevs.springsecurityjwt.models.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.management.relation.Role;
import java.util.Optional;

@Repository
public interface IRolesRepo extends JpaRepository<Roles, Long> {
    //metodo para buscar un rol por su nombre-apodo
    Optional<Roles> findByname(String name);

}
