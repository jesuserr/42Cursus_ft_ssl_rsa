/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt_parser.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/01/26 19:15:30 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/12 20:52:23 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

static void	parse_options(int opt, t_encrypt_args *args)
{
	if (opt == 'h')
		print_encrypt_usage();
	else if (opt == 'a' && !args->base64_mode)
		args->base64_mode = true;
	else if (opt == 'd' && !args->decrypt_mode)
		args->decrypt_mode = true;
	else if (opt == 'e' && !args->encrypt_mode)
		args->encrypt_mode = true;
	else if (opt == 'i' && !args->input_from_file)
		set_flag_values(&args->input_from_file, &args->input_file_name);
	else if (opt == 'k' && !args->key_provided && str_is_hex(optarg, args))
		set_flag_values(&args->key_provided, &args->key);
	else if (opt == 'o' && !args->output_to_file)
	{
		args->output_to_file = true;
		args->output_fd = open(optarg, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (args->output_fd == -1)
			print_encrypt_strerror_and_exit(optarg, args);
	}
	else if (opt == 'p' && !args->pass_provided && str_is_ascii(optarg, args))
		set_flag_values(&args->pass_provided, &args->pass);
	else if (opt == 's' && !args->salt_provided && str_is_hex(optarg, args))
		set_flag_values(&args->salt_provided, &args->salt);
	else if (opt == 'v' && !args->iv_provided && str_is_hex(optarg, args))
		set_flag_values(&args->iv_provided, &args->iv);
}

// Function deals with both binary and text files. 'isatty' function is used to
// check if the input is coming from a pipe. Message is read in chunks of
// BUFFER_SIZE bytes and with the help of 'realloc' and 'ft_memcpy', the whole
// message is stored in 'input_pipe'. If the file is empty, the program will not
// read anything and the input_pipe will be NULL.
// IMPORTANT: Since input can be binary, the message contained in 'input_pipe' 
// is not null-terminated, and therefore cannot be printed with 'printf'.
static void	parse_pipe(t_encrypt_args *args)
{
	char		buffer[BUFFER_SIZE];
	char		*temp;
	ssize_t		bytes_read;

	if (isatty(STDIN_FILENO) != 0)
		return ;
	bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
	while (bytes_read > 0)
	{
		temp = realloc(args->input_pipe, args->pipe_size + (size_t)bytes_read);
		if (!temp)
			print_encrypt_strerror_and_exit("realloc", args);
		args->input_pipe = temp;
		ft_memcpy(args->input_pipe + args->pipe_size, buffer, \
		(size_t)bytes_read);
		args->pipe_size += (size_t)bytes_read;
		bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
	}
	if (bytes_read < 0)
	{
		free(args->input_pipe);
		print_error_and_exit("Error reading from pipe");
	}
}

// Uses 'mmap' to map the entire file into memory in one shot. Way more 
// efficient than reading the file multiple times. File size is kept for the
// encrypt functions to know how many bytes to read (specially for binary files)
// and also for the 'munmap' function to know how many bytes to unmap when the
// program finishes. Empty file case is handled too, otherwise 'mmap' would
// fail. Since whitespaces and newlines must be removed from the decoded 
// message (when flag -a is used), mmap is opened as PROT_READ | PROT_WRITE to
// allow this space of memory to be modified.
static void	parse_file_content(t_encrypt_args *args, char *file_name)
{
	int			fd;
	struct stat	file_stat;
	void		*file_content;

	fd = open(file_name, O_RDONLY);
	if (fd < 0)
		print_encrypt_strerror_and_exit(file_name, args);
	if (fstat(fd, &file_stat) < 0)
		print_encrypt_strerror_and_exit(file_name, args);
	if (file_stat.st_size > 0)
	{
		file_content = mmap(NULL, (size_t)file_stat.st_size, \
		PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (file_content == MAP_FAILED)
		{
			close(fd);
			print_encrypt_strerror_and_exit("mmap", args);
		}
		args->input_file = (char *)file_content;
	}
	else
		args->input_file = "";
	close(fd);
	args->input_file_size = (uint64_t)file_stat.st_size;
	args->input_file_name = file_name;
}

// Parses the encrypt function and stores it in 'args->encrypt_function' to be
// called later by the function pointer array. No need of final 'else' since
// the pre-parser in main function already checks for valid function names.
static void	parse_encrypt_function(t_encrypt_args *args, char *function)
{
	if (!ft_strncmp(function, "des", 3) && ft_strlen(function) == 3)
		args->encrypt_function = 1;
	else if (!ft_strncmp(function, "des-ecb", 7) && ft_strlen(function) == 7)
		args->encrypt_function = 0;
	else if (!ft_strncmp(function, "des-cbc", 7) && ft_strlen(function) == 7)
		args->encrypt_function = 1;
	else if (!ft_strncmp(function, "des-cfb", 7) && ft_strlen(function) == 7)
		args->encrypt_function = 2;
	else if (!ft_strncmp(function, "des-ofb", 7) && ft_strlen(function) == 7)
		args->encrypt_function = 3;
}

// Parse main function.
// Default mode is encrypt and default output fd is stdout. Pipe will be read
// only if no file is provided, so only one input source is allowed.
void	parse_encrypt_arguments(int argc, char **argv, t_encrypt_args *args)
{
	int		opt;

	args->output_fd = STDOUT_FILENO;
	opt = getopt(argc, argv, "hadei:k:o:p:s:v:");
	while (opt != -1)
	{
		parse_options(opt, args);
		opt = getopt(argc, argv, "hadei:k:o:p:s:v:");
	}
	parse_encrypt_function(args, argv[optind]);
	errno = EINVAL;
	if (args->decrypt_mode && args->encrypt_mode)
		print_encrypt_strerror_and_exit("Cannot use both -d and -e flag", args);
	else if (!args->decrypt_mode && !args->encrypt_mode)
		args->encrypt_mode = true;
	if (++optind < argc)
		print_encrypt_strerror_and_exit("Not recognized option", args);
	if (!args->key_provided && !args->pass_provided)
		read_password_from_console(args);
	if (!args->input_from_file)
		parse_pipe(args);
	if (!argv[optind] && !args->input_pipe && !args->input_from_file)
		read_interactive_mode(&args->input_pipe, &args->pipe_size);
	else if (args->input_from_file)
		parse_file_content(args, args->input_file_name);
}
