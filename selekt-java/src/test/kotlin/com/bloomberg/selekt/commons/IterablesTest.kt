/*
 * Copyright 2022 Bloomberg Finance L.P.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bloomberg.selekt.commons

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

internal class IterablesTest {
    @Test
    fun forEachCatching() {
        List(2) { Any() }.forEachCatching {
            throw Exception("Oh no!")
        }.toList().let {
            assertEquals(2, it.size)
        }
    }

    @Test
    fun leftEmptyCartesianProduct() {
        assertEquals(emptyList(), (emptyList<Int>() * listOf(0, 1)).toList())
    }

    @Test
    fun rightEmptyCartesianProduct() {
        assertEquals(emptyList(), (listOf(0, 1) * emptyList<Int>()).toList())
    }

    @Test
    fun bothEmptyCartesianProduct() {
        assertEquals(emptyList(), (emptyList<Int>() * emptyList<Int>()).toList())
    }

    @Test
    fun hasNextEmptyIterable() {
        assertFalse(emptyIterable<Any>().iterator().hasNext())
    }

    @Test
    fun nextEmpty() {
        assertFailsWith<NoSuchElementException> { (emptyList<Int>() * emptyList<Int>()).iterator().next() }
    }

    @Test
    fun nextEmptyIterable() {
        assertFailsWith<NoSuchElementException> { emptyIterable<Int>().iterator().next() }
    }

    @Test
    fun nextFinished() {
        assertFailsWith<NoSuchElementException> {
            (listOf(0) * listOf(0)).iterator().run {
                next()
                next()
            }
        }
    }

    @Test
    fun smallCartesianProduct() {
        val left = listOf(0, 1)
        val right = listOf(2, 3)
        assertEquals(listOf(Pair(0, 2), Pair(0, 3), Pair(1, 2), Pair(1, 3)), (left * right).toList())
    }

    @Test
    fun smallArrayIterableProduct() {
        val left = arrayOf(0)
        val right = left.toList()
        assertEquals(listOf(Pair(0, 0)), (left * right).toList())
    }
}
