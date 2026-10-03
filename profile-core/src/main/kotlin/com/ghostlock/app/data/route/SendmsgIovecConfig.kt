package com.ghostlock.app.data.route

/**
 * `route.sendmsg_iovec` section. Mirrors the native section of the same name.
 *
 * The route has no geometry of its own: which waiter field a user iovec slot
 * lands on is a fixed property of the image (`__sys_sendmsg`'s on-stack iovec
 * array overlapping the stale `rt_mutex_waiter`), so the only keys the section
 * carries are the two execution knobs it shares with the select route - the
 * consumer delay that seeds the stamp window and the timeout that bounds it.
 *
 * Every field is optional: absence means "not provided".
 */
data class SendmsgIovecConfig(
    val enterDelayUs: UInt?,
    val timeoutUs: UInt?,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        enterDelayUs?.let { add("enter_delay_us" to it.toULong()) }
        timeoutUs?.let { add("timeout_us" to it.toULong()) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "enter_delay_us" -> copy(enterDelayUs = value.toUInt())
        "timeout_us" -> copy(timeoutUs = value.toUInt())
        else -> this
    }

    companion object {
        val EMPTY = SendmsgIovecConfig(null, null)

        fun from(value: (String) -> Long?): SendmsgIovecConfig = SendmsgIovecConfig(
            enterDelayUs = value("execution.routes.sendmsg_iovec.enter_delay_us")?.toUInt(),
            timeoutUs = value("execution.routes.sendmsg_iovec.timeout_us")?.toUInt(),
        )
    }
}
