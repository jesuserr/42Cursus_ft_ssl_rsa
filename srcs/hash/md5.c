/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/21 15:25:44 by jesuserr          #+#    #+#             */
/*   Updated: 2025/01/29 10:24:06 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Given a certain message, it is padded to a multiple of 512 bits and filled in
// accordance with the MD5 algorithm. Length of the message is stored as a 
// 64-bit integer in little-endian format. Initial values of the digest are set.
static void	create_padded_message(t_md5_data *ssl_data)
{
	uint64_t	len;
	uint64_t	len_bits;

	if (ssl_data->args->msg_origin == IS_FILE)
		len = ssl_data->args->file_size;
	else if (ssl_data->args->msg_origin == IS_PIPE)
		len = ssl_data->args->pipe_size;
	else
		len = ft_strlen(ssl_data->args->message);
	ssl_data->msg_len = len;
	if (len % MD5_BLOCK < MD5_BLOCK - 8 && len % MD5_BLOCK != 0)
		len = (len + MD5_BLOCK - 1) & ~(MD5_BLOCK - 1);
	else
		len = ((len + MD5_BLOCK - 1) & ~(MD5_BLOCK - 1)) + MD5_BLOCK;
	ssl_data->pad_len = len;
	ssl_data->pad_msg = ft_calloc(ssl_data->pad_len, sizeof(uint8_t));
	if (!ssl_data->pad_msg)
		print_hash_strerror_and_exit("ft_calloc", ssl_data->args);
	ft_memcpy(ssl_data->pad_msg, ssl_data->args->message, ssl_data->msg_len);
	ssl_data->pad_msg[ssl_data->msg_len] = (int8_t)0x80;
	len_bits = ssl_data->msg_len * 8;
	ft_memcpy(ssl_data->pad_msg + ssl_data->pad_len - 8, &len_bits, 8);
	ft_memcpy(ssl_data->digest, g_md5_inits, 16);
}

// MD5 algorithm core function.
static void	block_calculations(t_md5_data *ssl_data, uint8_t i, uint64_t j)
{
	uint32_t	tmp_b;
	uint64_t	index;

	if (i < 16)
		tmp_b = (ssl_data->state[B] & ssl_data->state[C]) | \
		(~ssl_data->state[B] & ssl_data->state[D]);
	else if (i >= 16 && i < 32)
		tmp_b = (ssl_data->state[B] & ssl_data->state[D]) | \
		(ssl_data->state[C] & ~ssl_data->state[D]);
	else if (i >= 32 && i < 48)
		tmp_b = ssl_data->state[B] ^ ssl_data->state[C] ^ ssl_data->state[D];
	else if (i >= 48 && i < 64)
		tmp_b = ssl_data->state[C] ^ (ssl_data->state[B] | ~ssl_data->state[D]);
	tmp_b = tmp_b + ssl_data->state[A] + g_md5_sine_add[i];
	index = (j * MD5_BLOCK) + (g_md5_index[i] * MD5_WORD_SIZE);
	tmp_b = tmp_b + *((uint32_t *)(ssl_data->pad_msg + index));
	tmp_b = left_rotation(tmp_b, g_md5_rotations[i]) + ssl_data->state[B];
	ssl_data->state[A] = ssl_data->state[D];
	ssl_data->state[D] = ssl_data->state[C];
	ssl_data->state[C] = ssl_data->state[B];
	ssl_data->state[B] = tmp_b;
}

// Print the digest in hexadecimal format in accordance with the combination of
// flags provided in the arguments. Although arguments are already inside 
// ssl_data, they are passed as a parameter to make the function more readable.
static void	print_md5_digest(t_md5_data *ssl_data, t_hash_args *args)
{
	uint8_t	i;

	i = 0;
	if (args->msg_origin == IS_PIPE && !args->echo_stdin && args->input_file)
		return ;
	if (args->quiet_mode)
	{
		if (args->echo_stdin && args->msg_origin == IS_PIPE)
			print_message_from_pipe(args);
		while (i < MD5_OUTPUT_SIZE / MD5_WORD_SIZE)
			print_hex_bytes((uint8_t *)&(ssl_data->digest[i++]), 0, 3);
		ft_printf("\n");
		return ;
	}
	print_prehash_output("MD5", args);
	while (i < MD5_OUTPUT_SIZE / MD5_WORD_SIZE)
		print_hex_bytes((uint8_t *)&(ssl_data->digest[i++]), 0, 3);
	if (args->reverse_output && args->msg_origin == IS_STRING)
		ft_printf(" \"%s\"", args->message);
	else if (args->reverse_output && args->msg_origin == IS_FILE)
		ft_printf(" %s", args->file_name);
	ft_printf("\n");
}

// Main function to calculate the MD5 digest.
void	md5_sum(t_hash_args *args)
{
	t_md5_data	ssl_data;
	uint8_t		i;
	uint64_t	j;

	ft_bzero(&ssl_data, sizeof(t_md5_data));
	ssl_data.args = args;
	create_padded_message(&ssl_data);
	j = 0;
	while (j < ssl_data.pad_len / MD5_BLOCK)
	{
		ft_memcpy(ssl_data.state, ssl_data.digest, 16);
		i = 0;
		while (i < MD5_BLOCK)
			block_calculations(&ssl_data, i++, j);
		ssl_data.digest[A] = ssl_data.digest[A] + ssl_data.state[A];
		ssl_data.digest[B] = ssl_data.digest[B] + ssl_data.state[B];
		ssl_data.digest[C] = ssl_data.digest[C] + ssl_data.state[C];
		ssl_data.digest[D] = ssl_data.digest[D] + ssl_data.state[D];
		j++;
	}
	print_md5_digest(&ssl_data, args);
	free(ssl_data.pad_msg);
}
