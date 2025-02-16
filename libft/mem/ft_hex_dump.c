/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_hex_dump.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/02 11:30:14 by jesuserr          #+#    #+#             */
/*   Updated: 2024/10/07 16:45:32 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include "ft_printf.h"

// Print byte in hexadecimal format
// hex_case = 55 for uppercase (87 for lowercase)
static void	print_hex_bytes(unsigned char *byte, size_t j)
{
	unsigned char	hex_case;

	hex_case = 87;
	if (*byte == 0)
		ft_printf("%s", GREY);
	else
		ft_printf("%s", LIGHT_WHITE);
	if ((*byte >> 4) < 10)
		ft_printf("%c", (*byte >> 4) + 48);
	else
		ft_printf("%c", (*byte >> 4) + hex_case);
	if ((*byte & 0x0F) < 10)
		ft_printf("%c ", (*byte & 0x0F) + 48);
	else
		ft_printf("%c ", (*byte & 0x0F) + hex_case);
	if (j % 8 == 7)
		ft_printf(" ");
}

// Print byte in ascii format if it's printable
static void	print_ascii_bytes(unsigned char *byte, size_t j)
{
	if (!(ft_isprint(*byte)))
		ft_printf(".");
	else
		ft_printf("%c", *byte);
	if (j % 8 == 7)
		ft_printf(" ");
}

// Casts (void *) to (unsigned char *) to access memory at byte level
void	ft_hex_dump(const void *src, size_t len, size_t bytes_per_line)
{
	unsigned char	*ptr;
	size_t			i;
	size_t			j;

	if (!src || (int)len < 1 || (int)bytes_per_line < 1)
		return ;
	i = 0;
	ptr = (unsigned char *)src;
	while (i < len)
	{
		ft_printf("%s%p:  ", BLUE, ptr + i);
		j = 0;
		while (j++ < bytes_per_line)
			print_hex_bytes(ptr + i + j - 1, j - 1);
		ft_printf(" %s", BLUE);
		j = 0;
		while (j++ < bytes_per_line)
			print_ascii_bytes(ptr + i + j - 1, j - 1);
		ft_printf("\n%s", RESET);
		i += bytes_per_line;
	}
}
