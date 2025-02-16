/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/15 17:53:09 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/04 20:39:38 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Although the encoded output is four bytes long, a fifth byte with '\0' value
// is used in order to print the result as a string using 'ft_putstr_fd'.
static void	print_encoded_triplet(uint8_t *triplet, int fd, uint8_t scenario)
{
	uint8_t		output[BASE64_DEC_BLOCKS + 1];

	output[0] = g_base64_table[triplet[0] >> 2];
	if (scenario == 1)
	{
		output[1] = g_base64_table[triplet[1] >> 4 | (triplet[0] & 0x03) << 4];
		output[2] = g_base64_table[triplet[2] >> 6 | (triplet[1] & 0x0F) << 2];
		output[3] = g_base64_table[triplet[2] & 0x3F];
	}
	else if (scenario == 2)
	{
		output[1] = g_base64_table[(triplet[0] & 0x03) << 4];
		output[2] = '=';
		output[3] = '=';
	}
	else if (scenario == 3)
	{
		output[1] = g_base64_table[triplet[1] >> 4 | (triplet[0] & 0x03) << 4];
		output[2] = g_base64_table[(triplet[1] & 0x0F) << 2];
		output[3] = '=';
	}
	output[4] = '\0';
	ft_putstr_fd((char *)output, fd);
}

// Process the message in blocks of 3 characters, encoding them using the
// 'g_base64_table' and bitwise operations. As a result, the four characters are
// stored in the output array and printed to the output file descriptor.
void	encode_message(t_encode_args *args)
{
	uint8_t		triplet[BASE64_ENC_BLOCKS];
	uint64_t	i;

	i = 0;
	while (i < (args->message_length / BASE64_ENC_BLOCKS) * 3)
	{
		ft_memcpy(triplet, args->message + i, BASE64_ENC_BLOCKS);
		print_encoded_triplet(triplet, args->output_fd, 1);
		i += BASE64_ENC_BLOCKS;
		if ((i * BASE64_DEC_BLOCKS / BASE64_ENC_BLOCKS) % BASE64_LINE == 0)
			ft_putstr_fd("\n", args->output_fd);
	}
	if (args->message_length % BASE64_ENC_BLOCKS == 1)
	{
		ft_memcpy(triplet, args->message + i, 1);
		print_encoded_triplet(triplet, args->output_fd, 2);
	}
	else if (args->message_length % BASE64_ENC_BLOCKS == 2)
	{
		ft_memcpy(triplet, args->message + i, 2);
		print_encoded_triplet(triplet, args->output_fd, 3);
	}
	ft_putstr_fd("\n", args->output_fd);
}

// Process the message in blocks of 4 characters, decoding them using the
// 'g_base64_reverse_table' and bitwise operations. As a result, the three bytes
// are stored in the output array and printed to the output file descriptor.
static void	decode_message(t_encode_args *args)
{
	uint8_t		quartet[BASE64_DEC_BLOCKS];
	uint8_t		output[BASE64_ENC_BLOCKS];
	uint8_t		reverse_table[4];
	uint64_t	i;

	i = 0;
	while (i < (args->message_length / BASE64_DEC_BLOCKS) * 4)
	{
		ft_memcpy(quartet, args->message + i, BASE64_DEC_BLOCKS);
		reverse_table[0] = g_base64_reverse_table[quartet[0]];
		reverse_table[1] = g_base64_reverse_table[quartet[1]];
		reverse_table[2] = g_base64_reverse_table[quartet[2]];
		reverse_table[3] = g_base64_reverse_table[quartet[3]];
		output[0] = (reverse_table[0] << 2) | (reverse_table[1] >> 4);
		output[1] = (reverse_table[1] << 4) | (reverse_table[2] >> 2);
		output[2] = (reverse_table[2] << 6) | reverse_table[3];
		ft_putchar_fd((char)output[0], args->output_fd);
		if (quartet[2] != '=')
			ft_putchar_fd((char)output[1], args->output_fd);
		if (quartet[3] != '=')
			ft_putchar_fd((char)output[2], args->output_fd);
		i += BASE64_DEC_BLOCKS;
	}
}

// After removing whitespaces and newlines, verifies if the message is properly
// encoded. The message must have a length multiple of 4 and if the penultimate
// character is '=', the last character must also be '='. The message must also
// contain only characters from 'g_base64_table' and '=' is only allowed in the
// last two positions of the message.
bool	proper_encoded_message(t_encode_args *args)
{
	uint64_t	i;

	if (args->message_length % BASE64_DEC_BLOCKS != 0)
		return (false);
	if (args->message[args->message_length - 2] == '=' && \
	args->message[args->message_length - 1] != '=')
		return (false);
	i = 0;
	while (i < args->message_length)
	{
		if (!ft_strchr((char *)g_base64_table, args->message[i]) \
		|| (args->message[i] == '=' && i < args->message_length - 2))
			return (false);
		i++;
	}
	return (true);
}

// Main function for base64 encoding/decoding.
void	base64(t_encode_args *args)
{
	if (args->encode_mode)
		encode_message(args);
	else if (args->decode_mode)
	{
		remove_message_whitespaces_and_newlines(args);
		if (!proper_encoded_message(args))
		{
			errno = EBADMSG;
			print_encode_strerror_and_exit("base64", args);
		}
		decode_message(args);
	}
}
