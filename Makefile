# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/11/19 17:09:51 by jesuserr          #+#    #+#              #
#    Updated: 2025/03/05 12:04:28 by jesuserr         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

LIBFT_DIR = libft/

NAME = ft_ssl
SRCS = 	main.c \
		utils/print_utils.c utils/bitwise_utils.c utils/common_utils.c \
	   	hash/hash_parser.c hash/hash_utils.c hash/md5.c hash/sha224.c \
		hash/sha256.c hash/sha384.c hash/sha512.c \
	   	encode/encode_parser.c encode/encode_utils.c encode/base64.c \
	   	encrypt/encrypt_parser.c encrypt/encrypt_utils.c encrypt/des_ecb.c \
		encrypt/encrypt_password.c encrypt/des_cbc.c encrypt/encrypt_pbkdf2.c \
		encrypt/encrypt_str_utils.c encrypt/encrypt_encode_utils.c \
		encrypt/encrypt_block_cipher.c encrypt/encrypt_sha256.c \
		encrypt/des_cfb.c encrypt/des_ofb.c \
		rsa/rsa_utils.c rsa/rsa_genrsa.c rsa/rsa_genrsa_parser.c \
		rsa/rsa_genrsa_maths.c rsa/rsa_genrsa_format.c rsa/rsa_rsa_parser.c \
		rsa/rsa_rsa.c rsa/rsa_encode_utils.c rsa/rsa_rsa_check.c \
		rsa/rsa_rsautl_parser.c rsa/rsa_rsautl.c
PATH_SRCS = ./srcs/
PATH_INCS = ./srcs/incs/
PATH_OBJS = ./objs/
PATH_DEPS = ./objs/

OBJS = $(addprefix $(PATH_OBJS), $(SRCS:.c=.o))
DEPS = $(addprefix $(PATH_DEPS), $(SRCS:.c=.d))

INCLUDE = -I./ -I./libft/includes/
RM = rm -f
CFLAGS = -Wall -Wextra -Werror -g -pedantic -Wshadow
LDFLAGS = -lbsd

NORM = $(addprefix $(PATH_SRCS), $(SRCS)) #$(PATH_INCS)*.h
GREEN = "\033[0;92m"
RED = "\033[0;91m"
BLUE = "\033[0;94m"
NC = "\033[37m"

all: makelibft $(NAME)

makelibft:
	@make --no-print-directory -C $(LIBFT_DIR)	
	@echo ${GREEN}"Libft Compiled!\n"${NC};

$(PATH_OBJS)%.o: $(PATH_SRCS)%.c Makefile
	@mkdir -p $(PATH_OBJS)
	@mkdir -p $(PATH_OBJS)/hash
	@mkdir -p $(PATH_OBJS)/encode
	@mkdir -p $(PATH_OBJS)/encrypt
	@mkdir -p $(PATH_OBJS)/utils
	@mkdir -p $(PATH_OBJS)/rsa
	$(CC) $(CFLAGS) -MMD $(INCLUDE) -c $< -o $@

$(NAME): $(OBJS) $(LIBFT_DIR)libft.a
	$(CC) $(CFLAGS) $(OBJS) $(LIBFT_DIR)libft.a -o $@ $(LDFLAGS)
	@echo ${GREEN}"ft_ssl Compiled!\n"${NC};
-include $(DEPS)

clean:
	@make clean --no-print-directory -C $(LIBFT_DIR)	
	@rm -rf $(PATH_OBJS)	
		
fclean:
	@make fclean --no-print-directory -C $(LIBFT_DIR)
	@rm -rf $(PATH_OBJS)
	$(RM) $(NAME)

norm:
	@echo ${BLUE}"\nChecking Norminette..."${NC}
	@if norminette $(NORM); then echo ${GREEN}"Norminette OK!\n"${NC}; \
	else echo ${RED}"Norminette KO!\n"${NC}; \
	fi

re: fclean all

.PHONY: all clean fclean re makelibft norm