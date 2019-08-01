package com.formacionbdi.springboot.app.oauth.security.event;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.formacionbdi.springboot.app.oauth.services.IUsuarioService;
import com.formacionbdi.springboot.app.usuarios.commons.models.entity.Usuario;

import feign.FeignException;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

	@Autowired
	private IUsuarioService usuarioService;

	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		UserDetails user = (UserDetails) authentication.getPrincipal();
		String username = user.getUsername();
		log.info("Success login: {}", username);
		Usuario usuario = usuarioService.findByUsername(username);
		if (usuario.getIntentos() != null && usuario.getIntentos() > 0) {
			usuario.setIntentos(0);
		}
		usuarioService.update(usuario, usuario.getId());
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		log.info("Error en el login: {}", exception.getMessage());
		String username = authentication.getName();
		try {
			Usuario usuario = usuarioService.findByUsername(username);
			if (usuario.getIntentos() == null) {
				usuario.setIntentos(0);
			}
			log.debug("Intentos actual es de: {}", usuario.getIntentos());
			usuario.setIntentos(usuario.getIntentos() + 1);
			log.debug("Intentos despúes es de: {}", usuario.getIntentos());

			if (usuario.getIntentos() >= 3) {
				log.error("El usuario {} ha sido deshabilitado por máximo de intentos", username);
				usuario.setEnabled(false);
			}
			usuarioService.update(usuario, usuario.getId());
		} catch (FeignException e) {
			log.error("El usuario {} no existe en el sistema", username);
		}

	}

}
