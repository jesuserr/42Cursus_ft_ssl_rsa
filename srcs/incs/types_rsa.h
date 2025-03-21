/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   types_rsa.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/17 19:20:59 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/06 19:28:59 by jesuserr         ###   ########.fr       */
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
# define PRIV_KEY_MAX_LENGTH	89U			// Private key max length in bytes
# define PUB_KEY_MAX_LENGTH		38U			// Public key max length in bytes
# define FIRST_RND_NBR			1U			// First random number generated
# define SECOND_RND_NBR			2U			// Second random number generated
# define RSA_PUB_KEY_HEADER		31U			// Header length RSA public key
# define RSA_PRIV_KEY_HEADER	32U			// Header length RSA private key
# define CRACK_START_TIMER		0U			// Start timer for crack function
# define CRACK_STOP_TIMER		1U			// Stop timer for crack function

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
	char		*input_pipe;
	char		*input_file;
	char		*message;
	char		*inkey_content;
	char		encoded_key[PRIV_KEY_MAX_LENGTH * 2];
	char		decoded_key[PRIV_KEY_MAX_LENGTH];
	char		*input_file_name;
	char		*output_file_name;
	char		*inkey_file_name;
	uint64_t	input_file_size;
	uint64_t	pipe_size;
	uint64_t	message_length;
	uint8_t		encoded_key_length;
	uint8_t		decoded_key_length;
	uint64_t	inkey_length;
	char		private_key[PRIV_KEY_MAX_LENGTH];
	char		public_key[PUB_KEY_MAX_LENGTH];
	int			output_fd;
	bool		input_from_file;
	bool		output_to_file;
	bool		verbose;
	bool		text;
	bool		noout;
	bool		modulus;
	bool		pub_out;
	bool		pub_in;
	bool		check;
	bool		inkey;
	bool		encrypt;
	bool		decrypt;
	bool		hexdump;
	bool		crack;
	uint8_t		rsa_function;
	uint8_t		pem_header;
	uint8_t		pem_footer;
	t_rsa_key	key;
}	t_rsa_args;

typedef struct s_miller_rabin_args
{
	uint64_t	s;
	uint64_t	d;
	uint64_t	a;
	uint64_t	x;
	uint64_t	y;
	uint64_t	s_copy;
}	t_miller_rabin_args;

enum	e_rsa_functions
{
	GENRSA,
	RSA,
	RSAUTL
};

// Hardcoded values for both keys. Since the key size is always 64 bits, some
// values can be hardcoded to simplify the key generation process.
// Maximum length expected for the private key is 89 bytes.
// Maximum length expected for the public key is 38 bytes.
// Structure according to the ASN.1 DER encoding.
static const u_int8_t	g_private_key[] = {
	0x30, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
	0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x00, 0x30, 0x00,
	0x02, 0x01, 0x00, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00};

static const u_int8_t	g_public_key[] = {
	0x30, 0x24, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x13, 0x00, 0x30, 0x10, 0x02, 0x09,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x01,
	0x00, 0x01};

#endif
