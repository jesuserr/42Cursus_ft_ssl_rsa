/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt_pbkdf2.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/01/30 16:03:09 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/12 13:06:42 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// # include <openssl/evp.h> and LDFLAGS = -lcrypto in Makefile
// openssl function to generate key with PBKDF2 - kept for reference
// derive_key_pbkdf2(args->pass, args->hex_salt, BLOCK_LENGTH, ITERATIONS, 
// BLOCK_LENGTH, args->hex_key);
/*
static void	derive_key_pbkdf2(const char *password, const unsigned char *salt, \
		int salt_len, int iterations, int key_len, unsigned char *output_key)
{
	if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, \
	iterations, EVP_sha256(), key_len, output_key) == 0)
		fprintf(stderr, "Error generating key with PBKDF2\n");
}
*/

// Password padding for HMAC_SHA256 - Just called once
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
static void	check_password_length(t_encrypt_args *args)
{
	t_hash_args	hash_args;

	if (ft_strlen(args->pass) > SHA256_BLOCK)
	{
		hash_args.message = args->pass;
		hash_args.pipe_size = ft_strlen(args->pass);
		sha256(&hash_args, args);
		ft_memcpy(args->hmac_data.k0, args->hmac_data.sha256_digest, \
		SHA256_OUTPUT_SIZE);
	}
	else if (ft_strlen(args->pass) < SHA256_BLOCK)
		ft_memcpy(args->hmac_data.k0, args->pass, ft_strlen(args->pass));
	else
		ft_memcpy(args->hmac_data.k0, args->pass, SHA256_BLOCK);
}

// HMAC_SHA256(Password, text) = 
// SHA256((K0 ⊕ opad) || SHA256((K0 ⊕ ipad) || text)
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
// Output returned in args->hmac_data.sha256_digest
static void	hmac_sha256(t_encrypt_args *args, uint8_t size)
{
	t_hash_args	hash_args;
	uint8_t		i;

	ft_memcpy(args->hmac_data.k0_ipad, args->hmac_data.k0, SHA256_BLOCK);
	ft_memcpy(args->hmac_data.k0_opad, args->hmac_data.k0, SHA256_BLOCK);
	i = 0;
	while (i < SHA256_BLOCK)
		args->hmac_data.k0_ipad[i++] ^= 0x36;
	ft_memcpy(args->hmac_data.append, args->hmac_data.k0_ipad, SHA256_BLOCK);
	ft_memcpy(args->hmac_data.append + SHA256_BLOCK, \
	args->hmac_data.prf_input, size);
	hash_args.message = (char *)args->hmac_data.append;
	hash_args.pipe_size = SHA256_BLOCK + size;
	sha256(&hash_args, args);
	i = 0;
	while (i < SHA256_BLOCK)
		args->hmac_data.k0_opad[i++] ^= 0x5C;
	ft_memcpy(args->hmac_data.append, args->hmac_data.k0_opad, SHA256_BLOCK);
	ft_memcpy(args->hmac_data.append + SHA256_BLOCK, \
	args->hmac_data.sha256_digest, SHA256_OUTPUT_SIZE);
	hash_args.message = (char *)args->hmac_data.append;
	hash_args.pipe_size = SHA256_BLOCK + SHA256_OUTPUT_SIZE;
	sha256(&hash_args, args);
}

// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
// https://en.wikipedia.org/wiki/PBKDF2
// Generate derived key with PBKDF2 using HMAC_SHA256
// DK = PBKDF2(HMAC_SHA256, pass, salt, ITERATIONS, BLOCK_LENGTH)
void	generate_derived_key(t_encrypt_args *args)
{
	uint8_t		j;	
	uint64_t	i;

	ft_bzero(&args->hmac_data, sizeof(t_hmac_data));
	check_password_length(args);
	ft_memcpy(args->hmac_data.prf_input, args->hex_salt, BLOCK_LENGTH);
	args->hmac_data.prf_input[11] = 0x01;
	hmac_sha256(args, FIRST_ITER_SIZE);
	ft_memcpy(args->hex_key, args->hmac_data.sha256_digest, BLOCK_LENGTH);
	i = 1;
	while (i < ITERATIONS)
	{
		ft_memcpy(args->hmac_data.prf_input, args->hmac_data.sha256_digest, \
		NEXT_ITERS_SIZE);
		hmac_sha256(args, NEXT_ITERS_SIZE);
		j = 0;
		while (j < BLOCK_LENGTH)
		{
			args->hex_key[j] ^= args->hmac_data.sha256_digest[j];
			j++;
		}
		i++;
	}
}
