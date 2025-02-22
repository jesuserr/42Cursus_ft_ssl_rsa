/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   types_rsa.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/17 19:20:59 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/22 17:34:04 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TYPES_RSA_H
# define TYPES_RSA_H

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              DEFINES
*/
# define RSA_KEY_LENGTH			8U			// Key length in bytes (64 bits)
# define MR_ITERATIONS			30U			// Iterations for Miller-Rabin test
# define PRIV_KEY_LENGTH		87U			// Private key length in bytes

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              STRUCTS
*/
typedef struct s_rsa_key
{
	uint32_t	p;
	uint32_t	q;
	uint64_t	n;
	uint64_t	phi;
	uint64_t	e;
	uint64_t	d;
	uint32_t	dmp1;
	uint32_t	dmq1;
	uint32_t	iqmp;
}	t_rsa_key;

typedef struct s_rsa_args
{
	char		*output_file_name;
	char		private_key[PRIV_KEY_LENGTH];
	int			output_fd;
	bool		output_to_file;
	uint8_t		rsa_function;
	t_rsa_key	key;
}	t_rsa_args;

typedef struct s_miller_rabin_args
{
	uint64_t	s;
	uint64_t	d;
	uint64_t	a;
	uint64_t	x;
	uint64_t	y;
}	t_miller_rabin_args;

enum	e_rsa_functions
{
	GENRSA,
	RSA,
	RSAUTL
};

// Hardcoded values for the private key. Since the length of the key is always
// 64 bits, we can hardcode some values to simplify the key generation process.
// 87 bytes length. Structure according to the ASN.1 DER encoding.
static const u_int8_t	g_private_key[] = {
	0x30, 0x55, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 
	0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x41, 0x30, 0x3f,
	0x02, 0x01, 0x00, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00, 0x00,
	0x00, 0x00, 0x00};

#endif
