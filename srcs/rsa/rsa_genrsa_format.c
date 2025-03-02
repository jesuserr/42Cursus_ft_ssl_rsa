/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa_format.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/23 20:32:46 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/01 23:24:47 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

#define INTEGER_TAG 			0x02
#define INITIAL_INDEX 			44
#define MASK_64_MSB_ACTIVE		0x0000000000000080
#define MASK_32_MSB_ACTIVE		0x00000080

// Modifies the endianess of the RSA key values to be stored in the private key
void	modify_key_values_endianness(t_rsa_key *key)
{
	modify_endianness_64_bits(&key->n);
	modify_endianness_64_bits(&key->d);
	modify_endianness_32_bits(&key->p);
	modify_endianness_32_bits(&key->q);
	modify_endianness_32_bits(&key->dmp1);
	modify_endianness_32_bits(&key->dmq1);
	modify_endianness_32_bits(&key->iqmp);
}

static uint8_t	insert_32bit_value(t_rsa_args *args, uint8_t i, uint32_t nbr)
{
	uint8_t	bytes;

	args->private_key[i++] = INTEGER_TAG;
	bytes = sizeof(uint32_t);
	if (nbr & MASK_32_MSB_ACTIVE)
		bytes++;
	args->private_key[i++] = bytes;
	i = i + bytes;
	ft_memcpy(args->private_key + i - sizeof(uint32_t), &nbr, sizeof(uint32_t));
	return (i);
}

static uint8_t	insert_64bit_value(t_rsa_args *args, uint8_t i, uint64_t nbr)
{
	uint8_t	bytes;

	bytes = sizeof(uint64_t);
	if (nbr & MASK_64_MSB_ACTIVE)
		bytes++;
	args->private_key[i++] = bytes;
	i = i + bytes;
	ft_memcpy(args->private_key + i - sizeof(uint64_t), &nbr, sizeof(uint64_t));
	return (i);
}

// https://en.wikipedia.org/wiki/ASN.1
// https://stackoverflow.com/questions/5974633/asn-1-der-formatted-private-key
// Generate RSA private key in ASN.1 DER format. If the most significant bit of
// a number is '1', an extra 00 byte is added to the integer to avoid confusion
// with negative numbers. Only applicable to d, dmp1, dmq1 and iqmp. Notice that
// masks are inverted since the endianness of all the numbers has been modified.
uint8_t	format_rsa_private_key(t_rsa_args *args)
{
	uint8_t	index;

	modify_key_values_endianness(&args->key);
	ft_memcpy(args->private_key, &g_private_key, sizeof(g_private_key));
	ft_memcpy(args->private_key + 30, &args->key.n, sizeof(args->key.n));
	index = INITIAL_INDEX;
	index = insert_64bit_value(args, index, args->key.d);
	args->private_key[index++] = INTEGER_TAG;
	args->private_key[index++] = sizeof(uint32_t) + 1;
	ft_memcpy(args->private_key + index + 1, &args->key.p, sizeof(uint32_t));
	index = index + sizeof(uint32_t) + 1;
	args->private_key[index++] = INTEGER_TAG;
	args->private_key[index++] = sizeof(uint32_t) + 1;
	ft_memcpy(args->private_key + index + 1, &args->key.q, sizeof(uint32_t));
	index = index + sizeof(uint32_t) + 1;
	index = insert_32bit_value(args, index, args->key.dmp1);
	index = insert_32bit_value(args, index, args->key.dmq1);
	index = insert_32bit_value(args, index, args->key.iqmp);
	args->private_key[1] = index - 2;
	args->private_key[21] = index - 22;
	args->private_key[23] = index - 24;
	return (index);
}
// Although doesn't has a impact on the key content, it should be checked the
// real significant bytes of a number and write next to the integer tag only the
// amount of bytes with relevant info and the number itself. Key will work fine
// but if passed through openssl it will be modified according to ASN.1 DER
// format.
