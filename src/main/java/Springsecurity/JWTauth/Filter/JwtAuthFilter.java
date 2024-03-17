package Springsecurity.JWTauth.Filter;


import Springsecurity.JWTauth.Service.JwtService; 
import Springsecurity.JWTauth.Service.UserInfoService; 
import jakarta.servlet.FilterChain; 
import jakarta.servlet.ServletException; 
import jakarta.servlet.http.HttpServletRequest; 
import jakarta.servlet.http.HttpServletResponse; 
import org.springframework.beans.factory.annotation.Autowired; 
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; 
import org.springframework.security.core.context.SecurityContextHolder; 
import org.springframework.security.core.userdetails.UserDetails; 
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource; 
import org.springframework.stereotype.Component; 
import org.springframework.web.filter.OncePerRequestFilter; 

import java.io.IOException; 

// This class helps us to validate the generated jwt token 
@Component
public class JwtAuthFilter extends OncePerRequestFilter { 

	@Autowired
	private JwtService jwtService; 

	@Autowired
	private UserInfoService userDetailsService; 

	@Override
	protected void doFilterInternal(@SuppressWarnings("null") HttpServletRequest request, @SuppressWarnings("null") HttpServletResponse response, @SuppressWarnings("null") FilterChain filterChain) throws ServletException, IOException { 
		String authHeader = request.getHeader("Authorization"); 
		String token = null; 
		String username = null; 
		if (authHeader != null && authHeader.startsWith("Bearer ")) { 
			token = authHeader.substring(7); 
			username = jwtService.extractUsername(token); 
		} 

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) { 
			UserDetails userDetails = userDetailsService.loadUserByUsername(username); 
			if (jwtService.validateToken(token, userDetails)) { 
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()); 
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); 
				SecurityContextHolder.getContext().setAuthentication(authToken); 
			} 
		} 
		filterChain.doFilter(request, response); 
	} 
} 
