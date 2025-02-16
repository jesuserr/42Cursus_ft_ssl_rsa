/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/01/26 19:23:26 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/12 20:49:52 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// At the contrary of the hashing functions, the encrypt function is just 
// called once, since the input can only come from one source. File has
// priority over pipe, so if both are provided, the pipe will be ignored.
void	calls_to_encrypt_function(t_encrypt_args *args)
{
	void	(*encrpyt_functions[])(t_encrypt_args *) = \
			{des_ecb, des_cbc, des_cfb, des_ofb};

	if (args->input_pipe)
	{
		args->message = args->input_pipe;
		args->message_length = args->pipe_size;
		encrpyt_functions[args->encrypt_function](args);
		free(args->input_pipe);
	}
	if (args->input_file)
	{
		args->message = args->input_file;
		args->message_length = args->input_file_size;
		encrpyt_functions[args->encrypt_function](args);
		if (args->input_file_size > 0)
			if (munmap(args->input_file, args->input_file_size) < 0)
				print_encrypt_strerror_and_exit("munmap", args);
	}
	if (args->output_to_file && args->output_fd != STDOUT_FILENO)
		if (close(args->output_fd) < 0)
			print_encrypt_strerror_and_exit("close", args);
	if (!args->pass_provided && args->pass)
		free(args->pass);
}

void	print_encrypt_usage(void)
{
	ft_printf("Usage\n"
		"  ./ft_ssl <command> [flags] [file]\n\n"
		"Cipher options:\n"
		"  command     des, des-ecb, des-cbc, des-cfb or des-ofb\n"
		"  -h          print help and exit\n"
		"  -a          decode/encode the input/output in base64\n"
		"  -d          decrypt mode\n"
		"  -e          encrypt mode (default)\n"
		"  -i <file>   input file\n"
		"  -k <key>    key in hexadecimal\n"
		"  -o <file>   output file\n"
		"  -p          password in ASCII\n"
		"  -s <salt>   salt in hexadecimal\n"
		"  -v          initialization vector in hexadecimal\n");
	exit(EXIT_SUCCESS);
}

// Prints system error message, releases allocated memory and file descriptor
// and exits with EXIT_FAILURE status.
void	print_encrypt_strerror_and_exit(char *msg, t_encrypt_args *args)
{
	ft_putstr_fd(msg, STDERR_FILENO);
	ft_putstr_fd(": ", STDERR_FILENO);
	ft_putstr_fd(strerror(errno), STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
	if (args->input_pipe)
		free(args->input_pipe);
	if (args->input_file)
		munmap(args->input_file, args->input_file_size);
	if (args->output_to_file && args->output_fd != STDOUT_FILENO)
		close(args->output_fd);
	if (!args->pass_provided && args->pass)
		free(args->pass);
	if (args->plaintext)
		free(args->plaintext);
	if (args->ciphertext)
		free(args->ciphertext);
	exit(EXIT_FAILURE);
}

// Permutate the bits of the message provided in 'src' and save it into 'dst' 
// using the given permutation table and its length.
// 'src' and 'dst' cannot be the same.
void	bitwise_permutation(const uint8_t *src, uint8_t *dst, \
		const uint8_t *table, uint8_t length)
{
	uint8_t	i;
	uint8_t	bit;

	i = 0;
	while (i < length)
	{
		bit = (src[(table[i] - 1) / 8] >> (7 - ((table[i] - 1) % 8))) & 0x01;
		dst[i / 8] |= (bit << (7 - i % 8));
		i++;
	}
}

// Implementation of PKCS#7 padding. The last block of the message is filled
// with the number of bytes that are needed to complete the block. If the 
// message is already a multiple of 8 bytes, a full block of padding is added.
// The message is copied to a new buffer called 'plaintext' and the padding is
// added at the end. Message length is updated to reflect the new length.
void	message_padding(t_encrypt_args *args)
{
	uint8_t		pad_len;
	uint64_t	i;

	pad_len = BLOCK_LENGTH - (args->message_length % BLOCK_LENGTH);
	args->plaintext = ft_calloc(args->message_length + pad_len, \
	sizeof(uint8_t));
	if (!args->plaintext)
		print_encrypt_strerror_and_exit("ft_calloc", args);
	ft_memcpy(args->plaintext, args->message, args->message_length);
	i = args->message_length;
	while (i < args->message_length + pad_len)
		args->plaintext[i++] = pad_len;
	args->message_length += pad_len;
}
