/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt_str_utils.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/01 13:25:55 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/06 19:01:56 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Returns true if the string is a valid hexadecimal string.
// Checks if the string is longer or shorter than 64 bits and prints a warning.
// No actions are taken if the string is shorter or longer than 64 bits.
// String is upper cased to simplify the conversion to bytes later.
bool	str_is_hex(char *str, t_encrypt_args *args)
{
	char	*copy;

	copy = str;
	while (*str)
	{
		if (!ft_isdigit(*str) && !ft_strchr("abcdefABCDEF", *str))
		{
			if (args->output_to_file && args->output_fd != STDOUT_FILENO)
				close(args->output_fd);
			print_error_and_exit("Invalid hexadecimal string");
		}
		*str = ft_toupper(*str);
		str++;
	}
	if (ft_strlen(copy) < 16)
	{
		ft_putstr_fd("Warning: hex string shorter than 64 bits", STDERR_FILENO);
		ft_putstr_fd(", padding with zeros\n", STDERR_FILENO);
	}
	else if (ft_strlen(copy) > 16)
	{
		ft_putstr_fd("Warning: hex string longer than 64 bits", STDERR_FILENO);
		ft_putstr_fd(", ignoring excess\n", STDERR_FILENO);
	}
	return (true);
}

// Returns true if the string is a valid printable ascii string.
bool	str_is_ascii(char *str, t_encrypt_args *args)
{
	while (*str)
	{
		if (!ft_isprint(*str))
		{
			if (args->output_to_file && args->output_fd != STDOUT_FILENO)
				close(args->output_fd);
			print_error_and_exit("Invalid ascii string");
		}
		str++;
	}
	return (true);
}

// Converts a string of hexadecimal characters to a byte array of 8 bytes.
// When end of string is reached, the rest of the bytes are set to 0x00.
void	convert_str_to_hex(const char *str, uint8_t *hex)
{
	uint8_t	i;
	uint8_t	j;

	i = 0;
	j = 0;
	while (i < BLOCK_LENGTH * 2)
	{
		if (str[i] >= '0' && str[i] <= '9')
			hex[j] = (str[i] - '0') << 4;
		else if (str[i] >= 'A' && str[i] <= 'F')
			hex[j] = (str[i] - 'A' + 10) << 4;
		else
			break ;
		i++;
		if (str[i] >= '0' && str[i] <= '9')
			hex[j] |= (str[i] - '0');
		else if (str[i] >= 'A' && str[i] <= 'F')
			hex[j] |= (str[i] - 'A' + 10);
		else
			break ;
		i++;
		j++;
	}
	while (++j < BLOCK_LENGTH)
		hex[j] = 0x00;
}
