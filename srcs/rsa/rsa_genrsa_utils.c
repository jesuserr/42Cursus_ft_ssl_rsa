/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa_utils.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/21 22:46:06 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/22 01:06:44 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// https://en.wikipedia.org/wiki/Modular_arithmetic
// Designed to compute the product of two large numbers modulo a third number
// without causing overflow (a * b mod n). Particularly important when working
// with uint64_t numbers, as the product of two uint64_t numbers can exceed the
// range of uint64_t.
uint64_t	modular_multiplication(uint64_t a, uint64_t b, uint64_t mod)
{
	uint64_t	result;

	result = 0;
	a = a % mod;
	while (b > 0)
	{
		if (b % 2 == 1)
			result = (result + a) % mod;
		a = (a * 2) % mod;
		b = b / 2;
	}
	return (result);
}

// https://en.wikipedia.org/wiki/Modular_exponentiation
// (Right-to-left binary method) Used to avoid overflow when calculating
// (a^d mod n). Allows to compute the result without ever needing to handle the
// potentially huge intermediate values of (a^d).
// 'mod' ('n') never will be 1 since it is filtered out before calling Miller-
// Rabin test. Checked anyways as extra security.
uint64_t	modular_exponentiation(uint64_t base, uint64_t exp, uint64_t mod)
{
	uint64_t	result;

	if (mod == 1)
		return (0);
	result = 1;
	base = base % mod;
	while (exp > 0)
	{
		if (exp % 2 == 1)
			result = modular_multiplication(result, base, mod);
		exp = exp >> 1;
		base = modular_multiplication(base, base, mod);
	}
	return (result);
}

// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
// Extended Euclidean algorithm to find the modular multiplicative inverse of
// 'e' modulo 'phi'.
uint64_t	modular_multiplicative_inverse(uint64_t e, uint64_t phi)
{
	int64_t		m0;
	int64_t		t;
	int64_t		q;
	int64_t		x0;
	int64_t		x1;

	m0 = phi;
	x0 = 0;
	x1 = 1;
	if (phi == 1)
		return (0);
	while (e > 1)
	{
		q = e / phi;
		t = phi;
		phi = e % phi;
		e = t;
		t = x0;
		x0 = x1 - q * x0;
		x1 = t;
	}
	if (x1 < 0)
		x1 += m0;
	return (x1);
}

// https://en.wikipedia.org/wiki/Greatest_common_divisor
// https://en.wikipedia.org/wiki/Euclidean_algorithm
// Calculate the greatest common divisor of two numbers 'a' and 'b'.
uint64_t	greatest_common_divisor(uint64_t a, uint64_t b)
{
	uint64_t	tmp;

	while (b != 0)
	{
		tmp = b;
		b = a % b;
		a = tmp;
	}
	return (a);
}

// Parser for genrsa command. Pretty simple since only needs to check for
// output file and help flag. If everything is correct, it calls the genrsa
// function.
void	parse_genrsa_arguments(char **argv, t_rsa_args *args)
{
	int	i;

	args->output_fd = STDOUT_FILENO;
	i = 2;
	while (argv[i])
	{
		if (!ft_strncmp(argv[i], "-h", 2) && ft_strlen(argv[i]) == 2)
			print_rsa_usage();
		else if (!ft_strncmp(argv[i], "-out", 4) && ft_strlen(argv[i]) == 4 && \
		argv[i + 1] && argv[i + 1][0] != '-' && !args->output_to_file)
		{
			args->output_to_file = true;
			args->output_file_name = argv[i + 1];
			i++;
		}
		else
			print_error_and_exit("Not recognized option");
		i++;
	}
	if (args->output_to_file)
	{
		args->output_fd = open(args->output_file_name, O_CREAT | O_WRONLY | \
		O_TRUNC, 0644);
		if (args->output_fd == -1)
			print_rsa_strerror_and_exit(args->output_file_name, args);
	}
	genrsa(args);
}
