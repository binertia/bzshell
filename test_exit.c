#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void sig_handler(int signal)
{
	if (signal == SIGINT)
	{
		// printf("");
		exit(130);
	}
	else if (signal == SIGQUIT)
		exit(131);
}

int main() {
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    signal(SIGINT,SIG_IGN);
    signal(SIGQUIT,SIG_IGN);
    if (pid == 0) {
        signal(SIGINT,sig_handler);
        signal(SIGQUIT,sig_handler);
        char *args[] = {"/bin/sleep","20", NULL};
        char *env[] = {NULL};
        // This is the child process
        printf("Child process\n");
	    execve("/bin/sleep", args, env);
        // Simulate a crash by dividing by zero
        exit(EXIT_SUCCESS);
    } else {
        // This is the parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("Child process terminated normally with exit status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child process terminated by signal %d\n", WTERMSIG(status));
        } else {
            printf("Child process terminated abnormally\n");
        }
    }

    return 0;
}

