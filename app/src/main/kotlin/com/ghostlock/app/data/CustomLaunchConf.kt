package com.ghostlock.app.data

/**
 * Serializes the app-configured custom launcher into the shell-sourceable file
 * the native root script reads from the run home directory.
 *
 * The file only declares three variables; the native script sources it, makes
 * the program executable when needed and starts it in the background. An empty
 * program keeps the launcher disabled.
 */
object CustomLaunchConf {
    const val FileName = ".ghostlock_launch.conf"

    fun render(program: String, arguments: String): String = buildString {
        append("# GhostLock custom launcher (written by the app).\n")
        append("GLK_LAUNCH_ENABLED=")
        append(if (program.isNotBlank()) "1" else "0")
        append('\n')
        append("GLK_LAUNCH_PROGRAM=")
        append(shellQuote(program.trim()))
        append('\n')
        append("GLK_LAUNCH_ARGS=")
        append(shellQuote(arguments.trim()))
        append('\n')
    }

    /** POSIX single-quote quoting: the value stays literal, embedded single
     *  quotes are closed, escaped and reopened. */
    private fun shellQuote(value: String): String =
        "'" + value.replace("'", "'\\''") + "'"
}
