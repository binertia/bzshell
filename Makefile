NAME := minishell

SRC	:=	bzshell.c\
		# parser/util.c\
		# parser/env_manage.c\
		# parser/make_string.c\
		# parser/group_token_list.c\
		# parser/helper_group_list_1.c\
		# parser/helper_group_list.c\
		# buildin/buildin_cd.c\
		# buildin/buildin_echo.c\
		# buildin/buildin_env.c\
		# buildin/buildin_exit.c\
		# buildin/buildin_export.c\
		# buildin/buildin_pwd.c\
		# buildin/buildin_unset.c\
		# parser/util_1.c\
		# parser/ft_itoa.c\
		# parser/run_and_check_buildin.c\
		# minishell_inchild.c\
		# parser/get_parser/get_stuff.c\
		# parser/get_parser/get_here_doc.c\
		# parser/get_parser/get_condition.c\
		# parser/get_parser/get_redir_parser.c\
		# parser/exec_thing.c\
		# parser/post_parser.c\
		# parser/check_parser/check_parser.c\
		# parser/check_parser/check_child_valid.c\
		# parser/check_parser/check_condition_valid.c\
		# parser/check_parser/check_extra_redir.c\
		# parser/check_parser/check_redir_valid_exec.c\
		# parser/parser.c

OBJ = $(SRC:.c=.o)

CC = cc

# RFLAGS =  -L/usr/local/opt/readline/lib -I/usr/local/opt/readline/include -lreadline
RFLAGS = -lreadline
#CFLAGS = -Wall -Wextra -Werror #-g -fsanitize=address

$(NAME) : $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(RFLAGS) -o $(NAME)
# $(MAKE) -C libft
# $(CC) $(CFLAGS) $(SRC) $(RFLAGS) -o $(NAME)

all: $(NAME)

bonus: $(NAME)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f minishell

# $(MAKE) -C libft fclean
# rm -f ./libft/libft.a

re : fclean all

.PHONY: all clean fclean re
