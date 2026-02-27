/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_ecb.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/01/29 11:18:14 by jesuserr          #+#    #+#             */
/*   Updated: 2026/02/26 16:01:28 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Auxiliary function to reduce the size of the 'des_ecb_encrypt' function and
// meet the 25 lines limit of the Norminette.
// Divides the message in blocks of 8 bytes and processes each block with the
// block cipher function. The result is stored in 'args->ciphertext'.
static void	ecb_encrypt_message(t_encrypt_args *args)
{
	uint64_t	i;

	i = 0;
	while (i < args->message_length)
	{
		ft_memcpy(args->input_block, args->plaintext + i, BLOCK_LENGTH);
		process_block_cipher(args);
		ft_memcpy(args->ciphertext + i, args->output_block, BLOCK_LENGTH);
		i += BLOCK_LENGTH;
	}
}

// ECB encryption main function.
// ciphertext allocation is message_length + 16 bytes in order to provide space
// for the salt and the salted__ string (if provided). If no salt is provided,
// the previously generated salt is added at the beginning of the ciphertext.
// At the end it encodes the encrypted message in base64 or prints it in binary,
// depending on the mode, to the specified output file descriptor.
static void	des_ecb_encrypt(t_encrypt_args *args)
{
	uint64_t	i;

	args->ciphertext = ft_calloc(args->message_length + 16, sizeof(uint8_t));
	if (!args->ciphertext)
		print_encrypt_strerror_and_exit("ft_calloc", args);
	ecb_encrypt_message(args);
	if (!args->salt_provided && !args->key_provided)
	{
		ft_memmove(args->ciphertext + SALT_TOTAL_LEN, args->ciphertext, \
		args->message_length);
		ft_memcpy(args->ciphertext, SALT_STR, SALT_LENGTH);
		ft_memcpy(args->ciphertext + SALT_LENGTH, args->hex_salt, SALT_LENGTH);
		args->message_length += SALT_TOTAL_LEN;
	}
	i = 0;
	if (args->base64_mode)
		encode_encrypted_message(args, args->ciphertext, args->message_length);
	else
		while (i < args->message_length)
			ft_putchar_fd(args->ciphertext[i++], args->output_fd);
	free(args->plaintext);
	free(args->ciphertext);
}

// Validate PKCS#7 padding byte before stripping it. A wrong key produces
// garbage output whose last byte may exceed BLOCK_LENGTH, causing 
// args->message_length underflow in the subtraction below and an out-of-bounds
// read (segfault). Known weakness: only the last byte is checked; if garbage
// falls in [1, 8] the check passes and garbled plaintext is silently printed.
static void	validate_pkcs7_padding(t_encrypt_args *args)
{
	if ((uint8_t)args->message[args->message_length - 1] == 0 || \
	(uint8_t)args->message[args->message_length - 1] > BLOCK_LENGTH)
	{
		errno = EINVAL;
		print_encrypt_strerror_and_exit("bad decrypt", args);
	}
}

// ECB decryption main function.
// Before calling this function, the message has been decoded from base64 (if
// it was encoded) and the salt been extracted from the message (if it was
// provided). After decrypting the message, message length is updated
// accordingly to the padding provided and the message is printed to the output
// file descriptor.
static void	des_ecb_decrypt(t_encrypt_args *args)
{
	uint64_t	i;

	i = 0;
	while (i < args->message_length)
	{
		ft_memcpy(args->input_block, args->message + i, BLOCK_LENGTH);
		process_block_cipher(args);
		ft_memcpy(args->message + i, args->output_block, BLOCK_LENGTH);
		i += BLOCK_LENGTH;
	}
	validate_pkcs7_padding(args);
	args->message_length -= args->message[args->message_length - 1];
	i = 0;
	while (i < args->message_length)
		ft_putchar_fd(args->message[i++], args->output_fd);
}

// Main function for des-ecb encryption/decryption.
void	des_ecb(t_encrypt_args *args)
{
	obtain_main_key(args);
	if (args->encrypt_mode)
	{
		generate_subkeys(args);
		message_padding(args);
		des_ecb_encrypt(args);
	}
	else if (args->decrypt_mode)
	{
		if (args->base64_mode)
			decode_encrypted_message(args);
		else
			is_base64_encoded_message(args);
		if (!ft_strncmp(args->message, SALT_STR, SALT_LENGTH))
			extract_salt(args);
		generate_subkeys(args);
		des_ecb_decrypt(args);
	}
}
