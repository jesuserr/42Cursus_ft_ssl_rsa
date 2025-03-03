/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/25 09:53:34 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/03 14:02:15 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

static void	output_encoded_key(t_rsa_args *args)
{
	uint8_t	key_len;

	ft_printf("writing RSA key\n");
	if (args->pub_out)
	{
		ft_putstr_fd("-----BEGIN RSA PUBLIC KEY-----\n", args->output_fd);
		key_len = format_rsa_public_key(args);
		encode_key(args, key_len);
		ft_putstr_fd("-----END RSA PUBLIC KEY-----\n", args->output_fd);
	}
	else
	{
		ft_putstr_fd("-----BEGIN RSA PRIVATE KEY-----\n", args->output_fd);
		key_len = format_rsa_private_key(args);
		encode_key(args, key_len);
		ft_putstr_fd("-----END RSA PRIVATE KEY-----\n", args->output_fd);
	}
}

// Prints out the key values in the desired format according to options -text
// and -modulus and also according to the type of key (private/public).
static void	print_key_values(t_rsa_args *args)
{
	if (args->text && args->pub_in)
	{
		ft_printf("Public-Key: (64 bit)\n");
		ft_printf("Modulus: ");
		print_uint64_number(args->key.n);
		ft_printf(" (0x%x%x)\n", args->key.n >> 32, (uint32_t)args->key.n);
		ft_printf("Exponent: %u (0x%x)\n", args->key.e, args->key.e);
	}
	else if (args->text && !args->pub_in)
	{
		ft_printf("Private-Key: (64 bit, 2 primes)\n");
		ft_printf("modulus: ");
		print_uint64_number(args->key.n);
		ft_printf(" (0x%x%x)\n", args->key.n >> 32, (uint32_t)args->key.n);
		ft_printf("publicExponent: %u (0x%x)\n", args->key.e, args->key.e);
		ft_printf("privateExponent: ");
		print_uint64_number(args->key.d);
		ft_printf(" (0x%x%x)\n", args->key.d >> 32, (uint32_t)args->key.d);
		ft_printf("prime1: %u (0x%x)\n", args->key.p, args->key.p);
		ft_printf("prime2: %u (0x%x)\n", args->key.q, args->key.q);
		ft_printf("exponent1: %u (0x%x)\n", args->key.dmp1, args->key.dmp1);
		ft_printf("exponent2: %u (0x%x)\n", args->key.dmq1, args->key.dmq1);
		ft_printf("coefficient: %u (0x%x)\n", args->key.iqmp, args->key.iqmp);
	}
	if (args->modulus)
	{
		ft_printf("Modulus=");
		ft_printf("%X%X\n", args->key.n >> 32, (uint32_t)args->key.n);
	}
}

// Extracts the key values from the decoded key. First of all, looks for the
// 0x0209 sequence that indicates the start of the modulus value and from then
// on, extracts n, e, d, p, q, dmp1, dmq1 and iqmp values. For public keys only
// extracts n and e values and then returns. It is assumed that n, e, p and q
// are always 9, 3, 5 and 5 bytes long, respectively. For d, dmp1, dmq1 and iqmp
// values, it is checked if these values are one bit longer than expected
// (8->9, 4->5, 4->5 and 4->5 bytes, respectively). If so, the index is
// incremented accordingly. Not checking if the length for these four values is
// smaller than expected (they could be...). Assumptions can be made since the
// key size is always 64 bits.
static void	extract_key_values(t_rsa_args *args)
{
	uint8_t	i;

	i = 0;
	while (i++ < args->decoded_key_length - 1)
		if (args->decoded_key[i] == 0x02 && args->decoded_key[i + 1] == 0x09)
			break ;
	if (i > args->decoded_key_length - 1)
		print_rsa_strerror_and_exit("RSA key not ok", args);
	ft_memcpy(&args->key.n, args->decoded_key + (i += 3), sizeof(uint64_t));
	ft_memcpy(&args->key.e, args->decoded_key + (i += 10), 3);
	if (args->pub_in)
		return ;
	i = i + 5;
	if (args->decoded_key[i - 1] > 8)
		i++;
	ft_memcpy(&args->key.d, args->decoded_key + i, sizeof(uint64_t));
	ft_memcpy(&args->key.p, args->decoded_key + (i += 11), sizeof(uint32_t));
	ft_memcpy(&args->key.q, args->decoded_key + (i += 7), sizeof(uint32_t));
	i = i + 6;
	if (args->decoded_key[i - 1] > 4)
		i++;
	ft_memcpy(&args->key.dmp1, args->decoded_key + i, sizeof(uint32_t));
	i = i + 6;
	if (args->decoded_key[i - 1] > 4)
		i++;
	ft_memcpy(&args->key.dmq1, args->decoded_key + i, sizeof(uint32_t));
	i = i + 6;
	if (args->decoded_key[i - 1] > 4)
		i++;
	ft_memcpy(&args->key.iqmp, args->decoded_key + i, sizeof(uint32_t));
}

// Verifies if the PEM header and footer are correct for either private or
// public keys. If correct, removes PEM header and footer and decodes the key.
static void	verify_and_decode_key(t_rsa_args *args)
{
	errno = EKEYREVOKED;
	if (!ft_strncmp(args->message, "-----BEGIN RSA PRIVATE KEY-----\n", 32) \
	&& !ft_strncmp(args->message + args->message_length - 31, \
	"\n-----END RSA PRIVATE KEY-----\n", 31) && !args->pub_in)
		args->pem_header = RSA_PRIV_KEY_HEADER;
	else if (!ft_strncmp(args->message, "-----BEGIN RSA PUBLIC KEY-----\n", 31) \
	&& !ft_strncmp(args->message + args->message_length - 30, \
	"\n-----END RSA PUBLIC KEY-----\n", 30) && args->pub_in)
		args->pem_header = RSA_PUB_KEY_HEADER;
	else
		print_rsa_strerror_and_exit("Error: Invalid key format", args);
	if (args->check && args->pub_in)
		print_rsa_strerror_and_exit("Error: Only private keys can be checked", \
		args);
	args->pem_footer = args->pem_header - 1;
	args->encoded_key_length = args->message_length - args->pem_footer - \
	args->pem_header;
	ft_memmove(args->encoded_key, args->message + args->pem_header, \
	args->encoded_key_length);
	decode_key(args);
	if (args->decoded_key_length - 2 != args->decoded_key[1])
		print_rsa_strerror_and_exit("Error: Invalid key length", args);
}

// RSA command main function.
void	rsa(t_rsa_args *args)
{
	verify_and_decode_key(args);
	extract_key_values(args);
	modify_key_values_endianness(&args->key);
	if (args->text || args->modulus)
		print_key_values(args);
	if (args->check)
		check_private_key(args);
	if (!args->noout)
		output_encoded_key(args);
}
