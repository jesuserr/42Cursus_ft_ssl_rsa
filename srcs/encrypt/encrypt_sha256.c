/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt_sha256.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/10 19:37:43 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/11 22:11:32 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Given a certain message, it is padded to a multiple of 512 bits and filled in
// accordance with the SHA256 algorithm. Length of the message is stored as a 
// 64-bit integer in big-endian format. Initial values of the digest are set.
// Reduced version of the same function in srcs/hash/sha256.c.
static void	create_padded_message(t_sha256_data *ssl_data, \
			t_encrypt_args *encrypt_args)
{
	uint64_t	len;
	uint64_t	len_bits;

	len = ssl_data->args->pipe_size;
	ssl_data->msg_len = len;
	if (len % SHA256_BLOCK < SHA256_BLOCK - 8 && len % SHA256_BLOCK != 0)
		len = (len + SHA256_BLOCK - 1) & ~(SHA256_BLOCK - 1);
	else
		len = ((len + SHA256_BLOCK - 1) & ~(SHA256_BLOCK - 1)) + SHA256_BLOCK;
	ssl_data->pad_len = len;
	ssl_data->pad_msg = ft_calloc(ssl_data->pad_len, sizeof(uint8_t));
	if (!ssl_data->pad_msg)
		print_encrypt_strerror_and_exit("ft_calloc", encrypt_args);
	ft_memcpy(ssl_data->pad_msg, ssl_data->args->message, ssl_data->msg_len);
	ssl_data->pad_msg[ssl_data->msg_len] = (int8_t)0x80;
	len_bits = ssl_data->msg_len * 8;
	modify_endianness_64_bits(&len_bits);
	ft_memcpy(ssl_data->pad_msg + ssl_data->pad_len - 8, &len_bits, 8);
	ft_memcpy(ssl_data->digest, g_sha256_inits, 32);
}

// Create message schedule for the current block of the message.
// 'w' used as a kind of alias for 'schedule' to make the code more readable.
// 'j' is the current block number.
// Same function as in srcs/hash/sha256.c.
static void	create_message_schedule(t_sha256_data *ssl_data, uint64_t j)
{
	uint8_t		i;
	uint32_t	*w;

	w = ssl_data->schedule;
	i = 0;
	while (i < 16)
	{
		w[i] = *(((uint32_t *)(ssl_data->pad_msg) + i + (j * 16)));
		modify_endianness_32_bits(&w[i]);
		i++;
	}
	while (i < 64)
	{
		ssl_data->s0 = right_rotation(w[i - 15], 7) ^ \
		right_rotation(w[i - 15], 18) ^ (w[i - 15] >> 3);
		ssl_data->s1 = right_rotation(w[i - 2], 17) ^ \
		right_rotation(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + ssl_data->s0 + w[i - 7] + ssl_data->s1;
		i++;
	}
	ft_memcpy(ssl_data->state, ssl_data->digest, 32);
}

// Compression function for the current block of the message.
// 'state' used as a kind of alias for 'ssl_data->state' to make the code more
// readable. 'i' is the current round number (0-63).
// Same function as in srcs/hash/sha256.c.
static void	compression_function(t_sha256_data *ssl_data, uint8_t i)
{
	uint32_t	tmp1;
	uint32_t	tmp2;
	uint32_t	*state;

	state = ssl_data->state;
	ssl_data->s1 = right_rotation(state[E], 6) ^ right_rotation(state[E], 11) \
	^ right_rotation(state[E], 25);
	ssl_data->ch = (state[E] & state[F]) ^ ((~state[E]) & state[G]);
	tmp1 = state[H] + ssl_data->s1 + ssl_data->ch + g_sha256_roots_add[i] + \
	ssl_data->schedule[i];
	ssl_data->s0 = right_rotation(state[A], 2) ^ right_rotation(state[A], 13) \
	^ right_rotation(state[A], 22);
	ssl_data->maj = (state[A] & state[B]) ^ (state[A] & state[C]) ^ \
	(state[B] & state[C]);
	tmp2 = ssl_data->s0 + ssl_data->maj;
	state[H] = state[G];
	state[G] = state[F];
	state[F] = state[E];
	state[E] = state[D] + tmp1;
	state[D] = state[C];
	state[C] = state[B];
	state[B] = state[A];
	state[A] = tmp1 + tmp2;
}

// Convert the final digest to big-endian format and save it in encrypt_args.
static void	modify_digest(t_sha256_data *ssl_data, t_encrypt_args *encrypt_args)
{
	uint8_t	i;

	i = 0;
	while (i < 8)
		modify_endianness_32_bits(&ssl_data->digest[i++]);
	ft_memcpy(encrypt_args->hmac_data.sha256_digest, ssl_data->digest, 32);
}

// Main function to calculate the SHA256 digest.
// Returns modified digest in big-endian format inside encrypt_args.
// encrypt_args passed to create_padded_message() in order to exit cleanly in
// case of error.
void	sha256(t_hash_args *args, t_encrypt_args *encrypt_args)
{
	t_sha256_data	ssl_data;
	uint8_t			i;
	uint64_t		j;

	ft_bzero(&ssl_data, sizeof(t_sha256_data));
	ssl_data.args = args;
	create_padded_message(&ssl_data, encrypt_args);
	j = 0;
	while (j < ssl_data.pad_len / SHA256_BLOCK)
	{
		create_message_schedule(&ssl_data, j++);
		i = 0;
		while (i < SHA256_BLOCK)
			compression_function(&ssl_data, i++);
		ssl_data.digest[A] += ssl_data.state[A];
		ssl_data.digest[B] += ssl_data.state[B];
		ssl_data.digest[C] += ssl_data.state[C];
		ssl_data.digest[D] += ssl_data.state[D];
		ssl_data.digest[E] += ssl_data.state[E];
		ssl_data.digest[F] += ssl_data.state[F];
		ssl_data.digest[G] += ssl_data.state[G];
		ssl_data.digest[H] += ssl_data.state[H];
	}
	modify_digest(&ssl_data, encrypt_args);
	free(ssl_data.pad_msg);
}
