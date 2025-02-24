/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa_maths.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/22 15:45:42 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/24 15:54:47 by jesuserr         ###   ########.fr       */
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
		if (b & 1)
		{
			if (result >= mod - a)
				result -= (mod - a);
			else
				result += a;
		}
		b >>= 1;
		if (a >= mod - a)
			a -= (mod - a);
		else
			a <<= 1;
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
