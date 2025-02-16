/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt_password.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/01/28 11:57:42 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/07 21:17:02 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Read and verify password from user and store it in 'args->pass'.
void	read_password_from_console(t_encrypt_args *args)
{
	char	buffer[1024];

	if (readpassphrase("enter encryption password:", buffer, sizeof(buffer), \
	RPP_ECHO_OFF) == NULL)
		print_encrypt_strerror_and_exit("readpassphrase", args);
	args->pass = ft_strdup(buffer);
	if (readpassphrase("Verifying - enter encryption password:", buffer, \
	sizeof(buffer), RPP_ECHO_OFF) == NULL)
		print_encrypt_strerror_and_exit("readpassphrase", args);
	if (ft_strlen(args->pass) != ft_strlen(buffer) || \
	(ft_strncmp(args->pass, buffer, ft_strlen(args->pass)) != 0))
	{
		errno = EINVAL;
		print_encrypt_strerror_and_exit("Password verification error", args);
	}
}

// Reading from /dev/urandom is the most secure way to generate a random salt.
// Better than using 'rand' or 'srand' functions.
void	generate_salt(uint8_t *salt, t_encrypt_args *args)
{
	int	fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		print_encrypt_strerror_and_exit("/dev/urandom", args);
	if (read(fd, salt, SALT_LENGTH) < 0)
		print_encrypt_strerror_and_exit("/dev/urandom", args);
	close(fd);
}

// Extracts the salt from the message and stores it in 'args->hex_salt' to
// generate the derived key. Updates 'args->message_length' and 'args->message'
// pointer to point to the next part of the message.
void	extract_salt(t_encrypt_args *args)
{
	ft_memcpy(args->hex_salt, args->message + SALT_LENGTH, SALT_LENGTH);
	generate_derived_key(args);
	args->message += SALT_TOTAL_LEN;
	args->message_length -= SALT_TOTAL_LEN;
}

// If a key is provided by user, it is converted from string to hexadecimal.
// If instead of a key, a password is provided, a derived key is generated from	
// the password and salt (if salt is not provided, it is generated too).
void	obtain_main_key(t_encrypt_args *args)
{
	if (args->key_provided)
		convert_str_to_hex(args->key, args->hex_key);
	else if (args->pass)
	{
		if (args->salt_provided)
			convert_str_to_hex(args->salt, args->hex_salt);
		else
			generate_salt(args->hex_salt, args);
		generate_derived_key(args);
	}
}
