/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/25 09:53:34 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/25 11:22:29 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// RSA command main function.
void	rsa(t_rsa_args *args)
{
	printf("RSA command\n");
	ft_hex_dump(args->message, args->message_length, 64);
	printf("message_length: %zu\n", args->message_length);
}
