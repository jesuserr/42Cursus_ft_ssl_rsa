/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/19 12:15:02 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/24 13:31:42 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Miller-Rabin_test
// Input #1: n > 2, an odd integer to be tested for primality
// Input #2: k, the number of rounds of testing to perform (accuracy) MAX: 255
// Output: "false" if n is found to be composite, otherwise probably prime.
// No need to initialize 'd' since 'n' will be odd and first while loop will run
// at least once. 'a' is initialized to 2 and incremented in each iteration.
// No need to initialize 'y' since it will be calculated in the second while
// loop which will run at least once.
bool	miller_rabin_test(uint64_t n, uint8_t k, bool verbose)
{
	t_miller_rabin_args	args;

	args.s = 1;
	while (((n - 1) % ((uint64_t)1 << args.s)) == 0)
		args.d = (n - 1) / ((uint64_t)1 << args.s++);
	args.s--;
	args.a = 2;
	while (k--)
	{
		args.x = modular_exponentiation(args.a, args.d, n);
		while (args.s > 0)
		{
			args.y = modular_multiplication(args.x, args.x, n);
			if (args.y == 1 && args.x != 1 && args.x != n - 1)
				return (false);
			args.x = args.y;
			args.s--;
		}
		if (args.y != 1)
			return (false);
		args.a++;
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
		if (args->key.n >= 0x8000000000000000)
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

// RSA key generation main function.
// Generates private key values and store them in the private key buffer with
// the proper endianness according (PKCS#8 / ASN.1 / DER). Then encodes the
// private key to base64 format (PEM) and is sent to the output file descriptor
// (terminal or output file).
void	genrsa(t_rsa_args *args)
{
	t_encode_args	encode_args;
	uint8_t			private_key_len;

	if (args->verbose)
		ft_printf("Generating RSA private key, 64 bit long modulus\n");
	key_calculation(args);
	modify_key_values_endianness(&args->key);
	private_key_len = format_rsa_private_key(args);
	if (args->verbose)
		ft_printf("\ne is 65537 (0x10001)\n");
	ft_putstr_fd("-----BEGIN PRIVATE KEY-----\n", args->output_fd);
	ft_bzero(&encode_args, sizeof(t_encode_args));
	encode_args.message = args->private_key;
	encode_args.message_length = private_key_len;
	encode_args.output_fd = args->output_fd;
	encode_message(&encode_args);
	ft_putstr_fd("-----END PRIVATE KEY-----\n", args->output_fd);
}

/*
	ft_hex_dump(args->private_key, sizeof(g_private_key), 24);
	printf("p: %u\nq: %u\nn: %lu\n", args->key.p, args->key.q, args->key.n);
	printf("phi: %lu\n", args->key.phi);
	printf("e: %lu\nd: %lu\n", args->key.e, args->key.d);
	printf("dmp1: %u\ndmq1: %u\n", args->key.dmp1, args->key.dmq1);
	printf("iqmp: %u\n", args->key.iqmp);
*/
