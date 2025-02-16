/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_ofb.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/12 20:42:08 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/12 20:59:04 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Divides the message in blocks of 8 bytes, and processes each block with the
// block cipher function according OFB. The result is stored in 
// 'args->ciphertext'.
static void	ofb_encrypt_message(t_encrypt_args *args)
{
	uint64_t	i;
	uint8_t		j;

	ft_memcpy(args->input_block, args->hex_iv, BLOCK_LENGTH);
	i = 0;
	while (i < args->message_length)
	{
		process_block_cipher(args);
		ft_memcpy(args->input_block, args->output_block, BLOCK_LENGTH);
		j = 0;
		while (j < BLOCK_LENGTH)
		{
			args->output_block[j] ^= (args->message + i)[j];
			j++;
		}
		ft_memcpy(args->ciphertext + i, args->output_block, BLOCK_LENGTH);
		i += BLOCK_LENGTH;
	}
}

// OFB encryption main function.
// ciphertext allocation is message_length + 16 bytes in order to provide space
// for the salt and the salted__ string (if provided). If no salt is provided,
// the previously generated salt is added at the beginning of the ciphertext.
// At the end it encodes the encrypted message in base64 or prints it in binary,
// depending on the mode, to the specified output file descriptor.
static void	des_ofb_encrypt(t_encrypt_args *args)
{
	uint64_t	i;

	args->ciphertext = ft_calloc(args->message_length + 16, sizeof(uint8_t));
	if (!args->ciphertext)
		print_encrypt_strerror_and_exit("ft_calloc", args);
	ofb_encrypt_message(args);
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
	free(args->ciphertext);
}

// OFB decryption main function.
// Before calling this function, the message has been decoded from base64 (if
// it was encoded) and the salt been extracted from the message (if it was
// provided). The message is decrypted with the keys not in reverse order.
static void	des_ofb_decrypt(t_encrypt_args *args)
{
	uint64_t	i;
	uint8_t		j;

	ft_memcpy(args->input_block, args->hex_iv, BLOCK_LENGTH);
	i = 0;
	while (i < args->message_length)
	{
		process_block_cipher(args);
		ft_memcpy(args->input_block, args->output_block, BLOCK_LENGTH);
		j = 0;
		while (j < BLOCK_LENGTH)
		{
			args->output_block[j] ^= (args->message + i)[j];
			j++;
		}
		ft_memcpy(args->message + i, args->output_block, BLOCK_LENGTH);
		i += BLOCK_LENGTH;
	}
	i = 0;
	while (i < args->message_length)
		ft_putchar_fd(args->message[i++], args->output_fd);
}

// Main function for des-ofb encryption/decryption.
// No padding. No need to reverse the keys for decryption.
void	des_ofb(t_encrypt_args *args)
{
	if (!args->iv_provided)
	{
		errno = EINVAL;
		print_encrypt_strerror_and_exit("Initialization vector error", args);
	}
	convert_str_to_hex(args->iv, args->hex_iv);
	obtain_main_key(args);
	if (args->encrypt_mode)
	{
		generate_subkeys(args);
		des_ofb_encrypt(args);
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
		des_ofb_decrypt(args);
	}
}
