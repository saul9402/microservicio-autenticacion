package com.formacionbdi.springboot.app.oauth.services;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.formacionbdi.springboot.app.oauth.clients.UsuarioFeignClient;
import com.formacionbdi.springboot.app.usuarios.commons.models.entity.Usuario;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UsuarioService implements UserDetailsService, IUsuarioService{

	@Autowired
	private UsuarioFeignClient client;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = findByUsername(username);

		if (usuario == null) {
			log.error("Error en el login, no existe el usuario '{}' en el sistema", username);
			throw new UsernameNotFoundException(
					"Error en el login, no existe el usuario '" + username + "' en el sistema");
		}

		List<GrantedAuthority> authorities = 
				usuario.getRoles()
				.stream()
				.map(role -> {
					return new SimpleGrantedAuthority(role.getNombre());
				})
				.peek(authority -> log.info("Role: {}", authority.getAuthority()))
				.collect(Collectors.toList());
		log.info("Usuario Autenticado {}", username);
		return new User(username, usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
	}

	@Override
	public Usuario findByUsername(String username) {
		Usuario usuario = client.findByUsername(username);
		return usuario;
	}

}
