/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   common_utils.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/15 13:58:37 by jesuserr          #+#    #+#             */
/*   Updated: 2025/01/29 12:29:45 by jesuserr         ###   ########.fr       */
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
