/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/25 09:53:34 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/01 20:11:23 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

void	process_key(t_rsa_args *args)
{
	printf("Decoding key\n");
	errno = EKEYREVOKED;
	if (!ft_strncmp(args->message, "-----BEGIN RSA PRIVATE KEY-----\n", 32) \
	&& !ft_strncmp(args->message + args->message_length - 31, \
	"\n-----END RSA PRIVATE KEY-----\n", 31))
		args->pem_header = RSA_PRIV_KEY_HEADER;
	else if (!ft_strncmp(args->message, "-----BEGIN RSA PUBLIC KEY-----\n", 31) \
	&& !ft_strncmp(args->message + args->message_length - 30, \
	"\n-----END RSA PUBLIC KEY-----\n", 30))
		args->pem_header = RSA_PUB_KEY_HEADER;
	else
		print_rsa_strerror_and_exit("Error: Invalid key format", args);
	args->pem_footer = args->pem_header - 1;
	args->encoded_key_length = args->message_length - args->pem_footer - \
	args->pem_header;
	ft_memmove(args->encoded_key, args->message + args->pem_header, \
	args->encoded_key_length);
	ft_printf("Encoded key without header and footer:\n");
	ft_hex_dump(args->encoded_key, args->message_length, 32);
	decode_key(args);
	ft_printf("Decoded key:\n");
	ft_hex_dump(args->decoded_key, args->decoded_key_length, 16);
	ft_printf("Decoded key length: %u\n", args->decoded_key_length);
}

// RSA command main function.
void	rsa(t_rsa_args *args)
{
	ft_printf("Encoded key:\n");
	ft_hex_dump(args->message, args->message_length, 32);
	printf("message_length: %zu\n", args->message_length);
	process_key(args);
}
