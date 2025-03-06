/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsautl.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/03/05 12:03:38 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/06 15:35:10 by jesuserr         ###   ########.fr       */
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

// https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm
// Since the algorithm is probabilistic, it may fail to find a factor. In that
// case 'false' will be returned and the brute force algorithm executed.
static bool	pollard_rho_algorithm(t_rsa_args *args)
{
	uint64_t	x;
	uint64_t	y;

	ft_printf("Cracking public RSA key, using Pollard's rho algorithm,");
	ft_printf(" please wait... ");
	x = 2;
	y = x;
	args->key.p = 1;
	while (args->key.p == 1)
	{
		x = modular_multiplication(x, x, args->key.n) + 1;
		y = modular_multiplication(y, y, args->key.n) + 1;
		y = modular_multiplication(y, y, args->key.n) + 1;
		args->key.p = greatest_common_divisor(llabs((int64_t)(x - y)), \
		args->key.n);
	}
	if (args->key.p == args->key.n)
		return (false);
	args->key.q = args->key.n / args->key.p;
	ft_printf(" Done!!\nn: ");
	print_uint64_number(args->key.n);
	ft_printf("\np: %u\nq: %u\nDecrypted message: ", args->key.p, args->key.q);
	args->key.phi = (uint64_t)(args->key.p - 1) * (uint64_t)(args->key.q - 1);
	args->key.d = modular_multiplicative_inverse(args->key.e, args->key.phi);
	return (true);
}

static void	brute_force_cracker(t_rsa_args *args)
{
	uint64_t	i;

	i = UINT32_MAX / 2;
	ft_printf("Cracking public RSA key, using brute force, please wait... ");
	while (i < args->key.n)
	{
		if (args->key.n % i == 0)
		{
			args->key.p = i;
			args->key.q = args->key.n / i;
			ft_printf(" Done!!\nn: ");
			print_uint64_number(args->key.n);
			ft_printf("\np: %u\nq: %u\n", args->key.p, args->key.q);
			ft_printf("Decrypted message: ");
			args->key.phi = (uint64_t)(args->key.p - 1) * \
			(uint64_t)(args->key.q - 1);
			args->key.d = modular_multiplicative_inverse(args->key.e, \
			args->key.phi);
			break ;
		}
		i++;
	}
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
	else if (args->decrypt && !args->crack)
	{
		if (args->pub_in)
			print_rsa_strerror_and_exit("Error: Private key required", args);
		output = modular_exponentiation(input, args->key.d, args->key.n);
	}
	else if (args->decrypt && args->crack)
	{
		if (!pollard_rho_algorithm(args))
			brute_force_cracker(args);
		output = modular_exponentiation(input, args->key.d, args->key.n);
	}
	modify_endianness_64_bits(&output);
	if (args->hexdump)
		hexdump(args, output);
	else
		write(args->output_fd, &output, sizeof(uint64_t));
}
