package com.februus.securityfifthsixteen;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan("com.februus.securityfifthsixteen.controller")
public class SecurityfifthsixteenApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityfifthsixteenApplication.class, args);
	}

}
