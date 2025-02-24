/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/19 17:11:34 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/24 14:03:46 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              HEADERS
*/
# include "../../libft/includes/libft.h"			// libft library
# include "../../libft/includes/ft_printf.h"		// ft_printf
# include "../../libft/includes/get_next_line.h"	// get_next_line
# include <stdint.h>							// for fixed-width integer types
# include <stdbool.h>							// for booleans
# include "types_hash.h"						// for t_hash_args
# include "types_encode.h"						// for t_encode_args
# include "types_encrypt.h"						// for t_encrypt_args
# include "types_rsa.h"							// for t_rsa_args
# include "md5.h"								// for MD5 hash function
# include "sha256.h"							// for SHA256 hash function
# include "sha224.h"							// for SHA224 hash function
# include "sha384.h"							// for SHA384 hash function
# include "sha512.h"							// for SHA512 hash function
# include "base64.h"							// for base64 encode function
# include "des_ecb.h"						    // for des-ecb encrypt function
# include "des_cbc.h"						    // for des-cbc encrypt function
# include "des_cfb.h"						    // for des-cfb encrypt function
# include "des_ofb.h"						    // for des-cob encrypt function
# include "genrsa.h"						    // for genrsa function
# include <string.h>							// for strerror
# include <fcntl.h>								// for open
# include <errno.h>								// for errno
# include <sys/stat.h>							// for fstat
# include <sys/mman.h>							// for mmap/munmap
# include <bsd/readpassphrase.h>				// for readpassphrase
# include <bits/getopt_core.h>	// Delete, just to fix intellisense vscode error

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              DEFINES
*/
# define HASH_COMMAND       1           // Pre-parser detected a hash command
# define ENCODE_COMMAND     2           // Pre-parser detected an encode command
# define ENCRYPT_COMMAND    3           // Pre-parser detected encrypt command
# define RSA_COMMAND		4           // Pre-parser detected an RSA command

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                        FUNCTION PROTOTYPES
*/
/********************************** bitwise_utils.c ***************************/
uint32_t	right_rotation(uint32_t nbr, uint8_t bits);
uint32_t	left_rotation(uint32_t nbr, uint8_t bits);
void		modify_endianness_32_bits(uint32_t *nbr);
void		modify_endianness_64_bits(uint64_t *nbr);
uint64_t	right_rotation_64(uint64_t nbr, int8_t bits);

/********************************** common_utils.c ****************************/
void		read_interactive_mode(char **input_pipe, uint64_t *pipe_size);
void		set_flag_values(bool *boolean_field, char **string_field);
bool		check_if_only_digits(const char *str);
bool		string_to_uint64(const char *str, uint64_t *value);

/********************************** encode_parser.c ***************************/
void		parse_encode_arguments(int argc, char **argv, t_encode_args *args);

/********************************** encode_utils.c ****************************/
void		calls_to_decoding_function(t_encode_args *args);
void		print_encode_usage(void);
void		print_encode_strerror_and_exit(char *msg, t_encode_args *args);
void		remove_message_whitespaces_and_newlines(t_encode_args *args);

/********************************** encrypt_block_cipher.c ********************/
void		generate_subkeys(t_encrypt_args *args);
void		process_block_cipher(t_encrypt_args *args);

/********************************** encrypt_encode_utils.c ********************/
void		decode_base64_message(t_encode_args *args, char *msg, char *copy);
void		encode_encrypted_message(t_encrypt_args *args, \
			unsigned char *ciphertext, int ciphertext_len);
void		decode_encrypted_message(t_encrypt_args *args);
void		is_base64_encoded_message(t_encrypt_args *args);

/********************************** encrypt_hmac_sha256.c *********************/
void		sha256(t_hash_args *args, t_encrypt_args *encrypt_args);

/********************************** encrypt_parser.c **************************/
void		parse_encrypt_arguments(int argc, char **argv, t_encrypt_args *arg);

/********************************** encrypt_password.c ************************/
void		read_password_from_console(t_encrypt_args *args);
void		generate_salt(uint8_t *salt, t_encrypt_args *args);
void		extract_salt(t_encrypt_args *args);
void		obtain_main_key(t_encrypt_args *args);

/********************************** encrypt_pbkdf2.c **************************/
void		generate_derived_key(t_encrypt_args *args);

/********************************** encrypt_str_utils.c ***********************/
bool		str_is_hex(char *str, t_encrypt_args *args);
bool		str_is_ascii(char *str, t_encrypt_args *args);
void		convert_str_to_hex(const char *str, uint8_t *hex);

/********************************** encrypt_utils.c ***************************/
void		calls_to_encrypt_function(t_encrypt_args *args);
void		print_encrypt_usage(void);
void		print_encrypt_strerror_and_exit(char *msg, t_encrypt_args *args);
void		bitwise_permutation(const uint8_t *src, uint8_t *dst, \
			const uint8_t *table, uint8_t length);
void		message_padding(t_encrypt_args *args);

/********************************** hash_parser.c *****************************/
void		parse_hash_arguments(int argc, char **argv, t_hash_args *args);

/********************************** hash_utils.c ******************************/
void		calls_to_hashing_function(t_hash_args *args);
void		print_hash_usage(void);
void		print_hash_strerror_and_exit(char *msg, t_hash_args *args);
void		print_prehash_output(char *algorithm, t_hash_args *args);
void		print_message_from_pipe(t_hash_args *args);

/********************************** print_utils.c *****************************/
void		print_hex_bytes(uint8_t *byte, uint8_t start, uint8_t end);
void		print_error_and_exit(char *str);
void		print_total_usage(void);

/********************************** rsa_genrsa_format.c ***********************/
uint8_t		format_rsa_private_key(t_rsa_args *args);

/********************************** rsa_genrsa_maths.c ************************/
uint64_t	modular_multiplication(uint64_t a, uint64_t b, uint64_t mod);
uint64_t	modular_exponentiation(uint64_t base, uint64_t exp, uint64_t mod);
uint64_t	modular_multiplicative_inverse(uint64_t e, uint64_t phi);
uint64_t	greatest_common_divisor(uint64_t a, uint64_t b);

/********************************** rsa_genrsa_utils.c ************************/
void		parse_genrsa_arguments(char **argv, t_rsa_args *args);
void		modify_key_values_endianness(t_rsa_key *key);

/********************************** rsa_genrsa.c ******************************/
bool		miller_rabin_test(uint64_t n, uint8_t k, bool verbose);
void		genrsa(t_rsa_args *args);

/********************************** rsa_utils.c *******************************/
void		calls_to_rsa_function(t_rsa_args *args);
void		print_rsa_usage(void);
void		print_rsa_strerror_and_exit(char *msg, t_rsa_args *args);
void		choose_rsa_parsing(int argc, char **argv, t_rsa_args *args);

#endif
