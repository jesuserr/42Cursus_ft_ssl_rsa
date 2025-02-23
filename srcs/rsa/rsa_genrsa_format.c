/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa_format.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/23 20:32:46 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/23 22:26:06 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

#define INTEGER_TAG 			0x02
#define INITIAL_INDEX 			44
#define INT32_WITH_EXTRA_BYTE 	0x05
#define INT64_WITH_EXTRA_BYTE 	0x09
#define MASK_64_MSB_ACTIVE		0x0000000000000080
#define MASK_32_MSB_ACTIVE		0x00000080

// https://en.wikipedia.org/wiki/ASN.1
// https://stackoverflow.com/questions/5974633/asn-1-der-formatted-private-key
// Generate RSA private key in ASN.1 DER format. If the most significant bit of
// a number is '1', an extra 00 byte is added to the integer to avoid confusion
// with negative numbers. Only applicable to d, dmp1, dmq1 and iqmp. Notice that
// masks are inverted since the endianness of all the numbers has been modified.
uint8_t	format_rsa_private_key(t_rsa_args *args)
{
	uint8_t	i;

	ft_memcpy(args->private_key, &g_private_key, sizeof(g_private_key));
	ft_memcpy(args->private_key + 30, &args->key.n, sizeof(args->key.n));
	i = INITIAL_INDEX;
	if (args->key.d & MASK_64_MSB_ACTIVE)
	{
		args->private_key[i++] = INT64_WITH_EXTRA_BYTE;
		ft_memcpy(args->private_key + i + 1, &args->key.d, sizeof(uint64_t));
		i = i + INT64_WITH_EXTRA_BYTE;
	}
	else
	{
		args->private_key[i++] = sizeof(uint64_t);
		ft_memcpy(args->private_key + i, &args->key.d, sizeof(uint64_t));
		i = i + sizeof(uint64_t);
	}
	args->private_key[i++] = INTEGER_TAG;
	args->private_key[i++] = INT32_WITH_EXTRA_BYTE;
	ft_memcpy(args->private_key + i + 1, &args->key.p, sizeof(uint32_t));
	i = i + INT32_WITH_EXTRA_BYTE;
	args->private_key[i++] = INTEGER_TAG;
	args->private_key[i++] = INT32_WITH_EXTRA_BYTE;
	ft_memcpy(args->private_key + i + 1, &args->key.q, sizeof(uint32_t));
	i = i + INT32_WITH_EXTRA_BYTE;
	args->private_key[i++] = INTEGER_TAG;
	if (args->key.dmp1 & MASK_32_MSB_ACTIVE)
	{
		args->private_key[i++] = INT32_WITH_EXTRA_BYTE;
		ft_memcpy(args->private_key + i + 1, &args->key.dmp1, sizeof(uint32_t));
		i = i + INT32_WITH_EXTRA_BYTE;
	}
	else
	{
		args->private_key[i++] = sizeof(uint32_t);
		ft_memcpy(args->private_key + i, &args->key.dmp1, sizeof(uint32_t));
		i = i + sizeof(uint32_t);
	}
	args->private_key[i++] = INTEGER_TAG;
	if (args->key.dmq1 & MASK_32_MSB_ACTIVE)
	{
		args->private_key[i++] = INT32_WITH_EXTRA_BYTE;
		ft_memcpy(args->private_key + i + 1, &args->key.dmq1, sizeof(uint32_t));
		i = i + INT32_WITH_EXTRA_BYTE;
	}
	else
	{
		args->private_key[i++] = sizeof(uint32_t);
		ft_memcpy(args->private_key + i, &args->key.dmq1, sizeof(uint32_t));
		i = i + sizeof(uint32_t);
	}
	args->private_key[i++] = INTEGER_TAG;
	if (args->key.iqmp & MASK_32_MSB_ACTIVE)
	{
		args->private_key[i++] = INT32_WITH_EXTRA_BYTE;
		ft_memcpy(args->private_key + i + 1, &args->key.iqmp, sizeof(uint32_t));
		i = i + INT32_WITH_EXTRA_BYTE;
	}
	else
	{
		args->private_key[i++] = sizeof(uint32_t);
		ft_memcpy(args->private_key + i, &args->key.iqmp, sizeof(uint32_t));
		i = i + sizeof(uint32_t);
	}
	args->private_key[1] = i - 2;
	args->private_key[21] = i - 22;
	args->private_key[23] = i - 24;
	return (i);
}
// Although doesn't has a impact on the key content, it should be checked the
// real significant bytes of a number and write next to the integer tag only the
// amount of bytes with relevant info and the number itself. Key will work fine
// but if passed through openssl it will be modified according to ASN.1 DER
// format.
