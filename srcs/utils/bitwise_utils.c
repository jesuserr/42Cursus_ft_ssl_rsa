/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bitwise_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/03 10:40:34 by jesuserr          #+#    #+#             */
/*   Updated: 2025/01/29 10:34:31 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Rotate 32-bit number to the right by given number of bits (circular shift)
uint32_t	right_rotation(uint32_t nbr, uint8_t bits)
{
	if (bits > 0 && bits < 32)
		nbr = nbr >> bits | nbr << (32 - bits);
	return (nbr);
}

// Rotate 32-bit number to the left by given number of bits (circular shift)
uint32_t	left_rotation(uint32_t nbr, uint8_t bits)
{
	if (bits > 0 && bits < 32)
		nbr = nbr << bits | nbr >> (32 - bits);
	return (nbr);
}

// Modify endianness of 32-bit number
void	modify_endianness_32_bits(uint32_t *nbr)
{
	*nbr = ((*nbr >> 24) & 0x000000FF) | ((*nbr >> 8) & 0x0000FF00) | \
			((*nbr << 8) & 0x00FF0000) | ((*nbr << 24) & 0xFF000000);
}

// Modify endianness of 64-bit number
void	modify_endianness_64_bits(uint64_t *nbr)
{
	*nbr = ((*nbr >> 56) & 0x00000000000000FF) | \
			((*nbr >> 40) & 0x000000000000FF00) | \
			((*nbr >> 24) & 0x0000000000FF0000) | \
			((*nbr >> 8) & 0x00000000FF000000) | \
			((*nbr << 8) & 0x000000FF00000000) | \
			((*nbr << 24) & 0x0000FF0000000000) | \
			((*nbr << 40) & 0x00FF000000000000) | \
			((*nbr << 56) & 0xFF00000000000000);
}

// Rotate 64-bit number to the right by given number of bits (circular shift)
uint64_t	right_rotation_64(uint64_t nbr, int8_t bits)
{
	if (bits > 0 && bits < 64)
		nbr = nbr >> bits | nbr << (64 - bits);
	return (nbr);
}
