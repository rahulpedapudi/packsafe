"""Exit codes for the PackSafe CLI.

One contract for every command, so a script can branch on *why* something failed rather
than parsing output. Documented in the README-facing help text of each command.
"""

# The package was analyzed and the policy said no. Distinct from every failure mode:
# nothing went wrong, the answer is simply "do not install this".
EXIT_BLOCKED = 4

# The package manager was found and run, and it failed. Its own exit code is preserved
# in the log rather than replaced.
EXIT_INSTALL_FAILED = 5
