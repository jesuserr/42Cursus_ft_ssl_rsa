/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsautl.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/03/05 12:03:38 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/05 18:58:10 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Verifies if the PEM header and footer are correct for either private or
// public keys. If correct, removes PEM header and footer and decodes the key.
static void	verify_and_decode_key(t_rsa_args *args)
{
	errno = EKEYREVOKED;
	if (!ft_strncmp(args->inkey_content, "-----BEGIN RSA PRIVATE KEY-----\n", \
	32) && !ft_strncmp(args->inkey_content + args->inkey_length - 31, \
	"\n-----END RSA PRIVATE KEY-----\n", 31) && !args->pub_in)
		args->pem_header = RSA_PRIV_KEY_HEADER;
	else if (!ft_strncmp(args->inkey_content, "-----BEGIN RSA PUBLIC KEY-----\n"\
	, 31) && !ft_strncmp(args->inkey_content + args->inkey_length - 30, \
	"\n-----END RSA PUBLIC KEY-----\n", 30) && args->pub_in)
		args->pem_header = RSA_PUB_KEY_HEADER;
	else
		print_rsa_strerror_and_exit("Error: Invalid key format", args);
	args->pem_footer = args->pem_header - 1;
	args->encoded_key_length = args->inkey_length - args->pem_footer - \
	args->pem_header;
	ft_memmove(args->encoded_key, args->inkey_content + args->pem_header, \
	args->encoded_key_length);
	decode_key(args);
	if (args->decoded_key_length - 2 != args->decoded_key[1])
		print_rsa_strerror_and_exit("Error: Invalid key length", args);
}

static void	hexdump(t_rsa_args *args, uint64_t output)
{
	int	stdout_backup;

	stdout_backup = dup(STDOUT_FILENO);
	dup2(args->output_fd, STDOUT_FILENO);
	ft_hex_dump(&output, sizeof(uint64_t), sizeof(uint64_t));
	dup2(stdout_backup, STDOUT_FILENO);
	close(stdout_backup);
}

// RSAUTL command main function.
void	rsautl(t_rsa_args *args)
{
	uint64_t	input;
	uint64_t	output;

	input = 0;
	verify_and_decode_key(args);
	extract_key_values(args);
	modify_key_values_endianness(&args->key);
	ft_memcpy(&input, args->message, args->message_length);
	modify_endianness_64_bits(&input);
	if (args->encrypt)
		output = modular_exponentiation(input, args->key.e, args->key.n);
	else if (args->decrypt)
	{
		if (args->pub_in)
			print_rsa_strerror_and_exit("Error: Private key required", args);
		output = modular_exponentiation(input, args->key.d, args->key.n);
	}
	modify_endianness_64_bits(&output);
	if (args->hexdump)
		hexdump(args, output);
	else
		write(args->output_fd, &output, sizeof(uint64_t));
}
