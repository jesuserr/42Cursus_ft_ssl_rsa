/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   common_utils.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/15 13:58:37 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/24 14:03:34 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Reads from standard input and stores the string in the 'args->input_pipe'.
// Uses 'gnl_strjoin' to concatenate the input lines and using the flag 'erase'
// set to 1,  frees the previous content of the 'input_pipe' field.
void	read_interactive_mode(char **input_pipe, uint64_t *pipe_size)
{
	char	*input;

	input = get_next_line(STDIN_FILENO);
	*input_pipe = ft_strdup("");
	while (input)
	{
		*input_pipe = gnl_strjoin(*input_pipe, input, 1);
		free(input);
		input = get_next_line(STDIN_FILENO);
	}
	*pipe_size = ft_strlen(*input_pipe);
	free(input);
}

// Auxiliary function to reduce 'parse_options' function size.
void	set_flag_values(bool *boolean_field, char **string_field)
{
	*boolean_field = true;
	*string_field = optarg;
}

// Checks if the string is composed only by digits, in that case returns true.
bool	check_if_only_digits(const char *str)
{
	int	i;

	i = 0;
	while (str[i])
	{
		if (!ft_isdigit(str[i]))
			return (false);
		i++;
	}
	return (true);
}

// Converts a string to uint64_t and return true if successful, false otherwise.
// The converted value is stored in the 'value' pointer.
// https://man7.org/linux/man-pages/man3/strtoul.3p.html
bool	string_to_uint64(const char *str, uint64_t *value)
{
	char	*endptr;

	errno = 0;
	*value = strtoull(str, &endptr, 10);
	if (errno != 0 || endptr == str || *endptr != '\0' || *value > UINT64_MAX)
		return (false);
	return (true);
}
