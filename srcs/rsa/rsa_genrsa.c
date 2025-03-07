/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/19 12:15:02 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/07 13:34:42 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Miller-Rabin_test
// Input #1: n > 2, an odd integer to be tested for primality
// Input #2: k, the number of rounds of testing to perform (accuracy)
// Maximum value of 'k' is 60, to avoid overflow of 'a' (see below).
// Output: "false" if n is found to be composite, otherwise probably prime.
// 'a' is initialized to 2 and doubled in each iteration. According to wikipedia
// it should be a random number in the range [2, n - 2], but subject does not
// allow rand() use and I don't want to call generate_random_number() each time.
bool	miller_rabin_test(uint64_t n, uint8_t k, bool verbose)
{
	t_miller_rabin_args	args;

	args.s = 0;
	args.d = n - 1;
	while ((args.d & 1) == 0)
	{
		args.d >>= 1;
		args.s++;
	}
	args.a = 2;
	args.s_copy = args.s;
	while (k--)
	{
		args.x = modular_exponentiation(args.a, args.d, n);
		args.s = args.s_copy;
		while (args.s-- > 0)
		{
			args.y = modular_multiplication(args.x, args.x, n);
			if (args.y == 1 && args.x != 1 && args.x != n - 1)
				return (false);
			args.x = args.y;
		}
		if (args.x != 1)
			return (false);
		args.a *= 2;
	}
	if (verbose)
		ft_printf("+");
	return (true);
}

// Generate a random 32-bit number reading from /dev/urandom. When cryptographic
// security is needed, reading from /dev/urandom is the most secure way to
// generate random numbers.
// A quick check is done to reject even numbers and numbers divisible by small
// primes (3, 5, 7 and 11) to eliminate composite numbers without needing the
// full Miller-Rabin test.
static uint32_t	generate_random_number(t_rsa_args *args, uint8_t number)
{
	int			fd;
	uint32_t	random_number;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		print_rsa_strerror_and_exit("/dev/urandom", args);
	while (1)
	{
		if (read(fd, &random_number, RSA_KEY_LENGTH / 2) < 0)
			print_rsa_strerror_and_exit("/dev/urandom", args);
		if (random_number % 2 == 0 || random_number % 3 == 0 || \
			random_number % 5 == 0 || random_number % 7 == 0 || \
			random_number % 11 == 0 || random_number <= 1)
			continue ;
		else
			break ;
	}
	close(fd);
	if (number == FIRST_RND_NBR && args->verbose)
		ft_printf(".");
	else if (number == SECOND_RND_NBR && args->verbose)
		ft_printf(",");
	return (random_number);
}

// Generate two random prime numbers 'p' and 'q' of 32 bits each. Calculate 'n'
// as the product of 'p' and 'q' until 'n' is greater than 2^63. Calculate 'phi'
// as (p - 1) * (q - 1). Choose 'e' as 65537, it is a common choice for RSA
// encryption. If 'e' and 'phi' are not coprime, an error is printed and the
// program exits. Calculate 'd' as the modular multiplicative inverse of 'e' 
// modulo 'phi'.
static void	key_calculation(t_rsa_args *args)
{
	while (1)
	{
		args->key.p = generate_random_number(args, FIRST_RND_NBR);
		if (!miller_rabin_test(args->key.p, MR_ITERATIONS, args->verbose))
			continue ;
		args->key.q = generate_random_number(args, SECOND_RND_NBR);
		while (!miller_rabin_test(args->key.q, MR_ITERATIONS, args->verbose))
			args->key.q = generate_random_number(args, SECOND_RND_NBR);
		args->key.n = (uint64_t)args->key.p * (uint64_t)args->key.q;
		if (args->key.n >= 0x8000000000000000 && args->key.p != args->key.q)
			break ;
		if (args->verbose)
			ft_printf("x");
	}
	args->key.phi = (uint64_t)(args->key.p - 1) * (uint64_t)(args->key.q - 1);
	args->key.e = 65537;
	errno = EKEYREVOKED;
	if (greatest_common_divisor(args->key.e, args->key.phi) != 1)
		print_rsa_strerror_and_exit("Error: 'e' and 'phi' not coprime", args);
	args->key.d = modular_multiplicative_inverse(args->key.e, args->key.phi);
	args->key.dmp1 = args->key.d % (args->key.p - 1);
	args->key.dmq1 = args->key.d % (args->key.q - 1);
	args->key.iqmp = (uint32_t)modular_multiplicative_inverse(args->key.q, \
	args->key.p);
}

// GENRSA key generation main function.
// Generates private key values and store them in the private key buffer with
// the proper endianness according (PKCS#1 / ASN.1 / DER). Then encodes the
// private key to base64 format (PEM) and is sent to the output file descriptor
// (terminal or output file).
void	genrsa(t_rsa_args *args)
{
	uint8_t			private_key_len;

	if (args->verbose)
		ft_printf("Generating RSA private key, 64 bit long modulus\n");
	key_calculation(args);
	private_key_len = format_rsa_private_key(args);
	if (args->verbose)
		ft_printf("\ne is 65537 (0x10001)\n");
	ft_putstr_fd("-----BEGIN RSA PRIVATE KEY-----\n", args->output_fd);
	encode_key(args, private_key_len);
	ft_putstr_fd("-----END RSA PRIVATE KEY-----\n", args->output_fd);
}
