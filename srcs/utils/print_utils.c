/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_utils.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/22 22:21:30 by jesuserr          #+#    #+#             */
/*   Updated: 2026/02/27 15:43:27 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

static void	print_total_usage_continued(void);

// Prints given array of bytes in hexadecimal format. Depending on the 'start'
// and 'end' values, it prints the array in ascending or descending order to
// deal with different digest formats (big-endian / little-endian).
// 48 is ASCII code for '0', 87 is ASCII code for 'a'
void	print_hex_bytes(uint8_t *byte, uint8_t start, uint8_t end)
{
	bool	increase;

	increase = start < end;
	while (1)
	{
		if ((byte[start] >> 4) < 10)
			ft_printf("%c", (byte[start] >> 4) + 48);
		else
			ft_printf("%c", (byte[start] >> 4) + 87);
		if ((byte[start] & 0x0F) < 10)
			ft_printf("%c", (byte[start] & 0x0F) + 48);
		else
			ft_printf("%c", (byte[start] & 0x0F) + 87);
		if (start == end)
			break ;
		if (increase)
			start++;
		else
			start--;
	}
}

void	print_error_and_exit(char *str)
{
	ft_putstr_fd("ft_ssl: usage error: ", STDERR_FILENO);
	ft_putstr_fd(str, STDERR_FILENO);
	ft_putstr_fd("\nTry 'ft_ssl -h' for more information.\n", STDERR_FILENO);
	exit (EXIT_FAILURE);
}

void	print_total_usage(void)
{
	ft_printf("Usage\n  ./ft_ssl <command> [flags] [file]\n\n"
		"Hash options:\n  command     md5, sha224, sha256, sha384 or sha512\n"
		"  -h          print help and exit\n"
		"  -p          echo STDIN to STDOUT and append the checksum to STDOUT\n"
		"  -q          quiet mode\n"
		"  -r          reverse the format of the output\n"
		"  -s <string> print the sum of the given string\n\n"
		"Encode options:\n  command     base64\n"
		"  -h          print help and exit\n"
		"  -d          decode mode\n"
		"  -e          encode mode (default)\n"
		"  -i <file>   input file\n"
		"  -o <file>   output file\n\n"
		"Cipher options:\n  command     des, des-ecb, des-cbc, des-cfb, des-ofb"
		"\n  -h          print help and exit\n"
		"  -a          decode/encode the input/output in base64\n"
		"  -d          decrypt mode\n"
		"  -e          encrypt mode (default)\n"
		"  -i <file>   input file\n"
		"  -k <key>    key in hexadecimal\n"
		"  -o <file>   output file\n"
		"  -p          password in ASCII\n"
		"  -s <salt>   salt in hexadecimal\n"
		"  -v          initialization vector in hexadecimal\n\n");
	print_total_usage_continued();
}

static void	print_total_usage_continued(void)
{
	ft_printf(
		"RSA options:\n  command           genrsa, rsa, rsautl\n"
		"  -h                print help and exit\n"
		"  genrsa flags:\n"
		"    -out <file>     output file\n"
		"    -verbose        print details during key generation\n"
		"    -test <n> <p>   test if n is prime at p probability\n"
		"  rsa flags:\n"
		"    -in <file>      input file\n"
		"    -out <file>     output file\n"
		"    -text           print the key in plain text\n"
		"    -noout          do not output encoded version of key\n"
		"    -modulus        print value of key modulus\n"
		"    -check          verify key consistency\n"
		"    -pubin          read public key from input file\n"
		"    -pubout         print public key\n"
		"  rsautl flags:\n"
		"    -in <file>      input file\n"
		"    -out <file>     output file\n"
		"    -inkey <file>   input key (RSA private key by default)\n"
		"    -encrypt        encrypt input data with public key\n"
		"    -decrypt        decrypt input data with private key\n"
		"    -hexdump        print the key in hexadecimal\n"
		"    -crack          crack RSA public key\n");
	exit(EXIT_SUCCESS);
}

void	print_uint64_number(uint64_t nbr)
{
	if (nbr >= 10)
		print_uint64_number(nbr / 10);
	ft_putchar_fd((nbr % 10) + '0', STDOUT_FILENO);
}
