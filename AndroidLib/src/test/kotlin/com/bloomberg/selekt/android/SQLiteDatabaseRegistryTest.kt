/*
 * Copyright 2021 Bloomberg Finance L.P.
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

package com.bloomberg.selekt.android

import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.Test
import org.mockito.kotlin.mock

internal class SQLiteDatabaseRegistryTest {
    @Test
    fun registeringTwiceThrows() {
        mock<SQLiteDatabase>().let {
            SQLiteDatabaseRegistry.register(it)
            try {
                assertThatExceptionOfType(IllegalArgumentException::class.java).isThrownBy {
                    SQLiteDatabaseRegistry.register(it)
                }
            } finally {
                SQLiteDatabaseRegistry.unregister(it)
            }
        }
    }

    @Test
    fun unregisterThrows() {
        assertThatExceptionOfType(IllegalArgumentException::class.java).isThrownBy {
            SQLiteDatabaseRegistry.unregister(mock())
        }
    }
}
