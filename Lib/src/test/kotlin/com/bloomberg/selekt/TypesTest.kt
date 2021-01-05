/*
 * Copyright 2021 Bloomberg Finance L.P.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bloomberg.selekt

import org.junit.Rule
import org.junit.jupiter.api.Test
import org.junit.rules.DisableOnDebug
import org.junit.rules.RuleChain
import org.junit.rules.Timeout
import kotlin.test.assertEquals

internal class TypesTest {
    @Rule
    @JvmField
    val rule: RuleChain = RuleChain.outerRule(DisableOnDebug(Timeout.seconds(10L)))

    @Test
    fun any() {
        assertEquals(ColumnType.STRING, Any().toColumnType())
    }

    @Test
    fun byte() {
        assertEquals(ColumnType.INTEGER, 42.toByte().toColumnType())
    }

    @Test
    fun byteArray() {
        assertEquals(ColumnType.BLOB, byteArrayOf(42).toColumnType())
    }

    @Test
    fun double() {
        assertEquals(ColumnType.FLOAT, 42.0.toColumnType())
    }

    @Test
    fun float() {
        assertEquals(ColumnType.FLOAT, 42.0f.toColumnType())
    }

    @Test
    fun int() {
        assertEquals(ColumnType.INTEGER, 42.toColumnType())
    }

    @Test
    fun long() {
        assertEquals(ColumnType.INTEGER, 42L.toColumnType())
    }

    @Test
    fun nullable() {
        assertEquals(ColumnType.NULL, null.toColumnType())
    }

    @Test
    fun short() {
        assertEquals(ColumnType.INTEGER, 42.toShort().toColumnType())
    }

    @Test
    fun string() {
        assertEquals(ColumnType.STRING, "42".toColumnType())
    }
}
