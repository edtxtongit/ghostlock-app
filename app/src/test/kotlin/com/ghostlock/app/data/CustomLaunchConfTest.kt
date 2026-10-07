package com.ghostlock.app.data

import org.junit.Assert.assertTrue
import org.junit.Test

class CustomLaunchConfTest {
    @Test
    fun `blank program disables the launcher`() {
        val text = CustomLaunchConf.render("", "")
        assertTrue(text.contains("GLK_LAUNCH_ENABLED=0"))
    }

    @Test
    fun `program enables the launcher and keeps the value verbatim`() {
        val text = CustomLaunchConf.render("/data/local/tmp/my shell", "-c")
        assertTrue(text.contains("GLK_LAUNCH_ENABLED=1"))
        assertTrue(text.contains("GLK_LAUNCH_PROGRAM='/data/local/tmp/my shell'"))
        assertTrue(text.contains("GLK_LAUNCH_ARGS='-c'"))
    }

    @Test
    fun `embedded single quotes are escaped`() {
        val text = CustomLaunchConf.render("/x/it's", "a 'b'")
        assertTrue(text.contains("GLK_LAUNCH_PROGRAM='/x/it'\\''s'"))
        assertTrue(text.contains("GLK_LAUNCH_ARGS='a '\\''b'\\'''"))
    }
}
