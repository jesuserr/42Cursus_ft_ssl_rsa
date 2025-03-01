/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_encode_utils.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/26 09:40:59 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/01 20:01:13 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Encode key to base64 format and send it to the output file descriptor
// (terminal or output file).
void	encode_key(t_rsa_args *args, uint8_t key_length)
{
	t_encode_args	encode_args;

	ft_bzero(&encode_args, sizeof(t_encode_args));
	encode_args.message = args->private_key;
	encode_args.message_length = key_length;
	encode_args.output_fd = args->output_fd;
	encode_message(&encode_args);
}

// base64() is not called directly in order to handle properly when there is
// an error and then print_rsa_strerror_and_exit() is called. If base64() were
// called directly, the program would exit without freeing the right allocated
// memory.
void	decode_key(t_rsa_args *args)
{
	t_encode_args	decode_args;

	ft_bzero(&decode_args, sizeof(t_encode_args));
	decode_args.message = args->encoded_key;
	decode_args.message_length = args->encoded_key_length;
	remove_message_whitespaces_and_newlines(&decode_args);
	if (!proper_encoded_message(&decode_args))
	{
		errno = EBADMSG;
		print_rsa_strerror_and_exit("Invalid base64 message", args);
	}
	decode_base64_message(&decode_args, args->decoded_key, args->decoded_key);
	args->decoded_key_length = decode_args.message_length;
}
