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

import brave.Tracer;
import feign.FeignException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UsuarioService implements UserDetailsService, IUsuarioService {

	@Autowired
	private UsuarioFeignClient client;
	
	@Autowired
	private Tracer tracer;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		try {
			Usuario usuario = findByUsername(username);

			List<GrantedAuthority> authorities = usuario.getRoles().stream().map(role -> {
				return new SimpleGrantedAuthority(role.getNombre());
			}).peek(authority -> log.info("Role: {}", authority.getAuthority())).collect(Collectors.toList());

			log.info("Usuario Autenticado {}", username);

			return new User(username, usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);

		} catch (FeignException e) {
			String erroMessage = e.getMessage();
			log.error("Error en el login, no existe el usuario '{}' en el sistema", username);
			//con esto agregas un tag que quieras exportar en zipkin para poder verlo en la interfaz gráfica
			tracer.currentSpan().tag("error.mensaje", erroMessage);
			throw new UsernameNotFoundException(
					"Error en el login, no existe el usuario '" + username + "' en el sistema");
		}
	}

	@Override
	public Usuario findByUsername(String username) {
		Usuario usuario = client.findByUsername(username);
		return usuario;
	}

	@Override
	public Usuario update(Usuario usuario, Long id) {
		return client.update(usuario, id);
	}

}
