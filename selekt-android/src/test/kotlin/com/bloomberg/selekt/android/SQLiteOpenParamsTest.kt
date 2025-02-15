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

package com.bloomberg.selekt.android

import com.bloomberg.selekt.android.SQLiteOpenParams.Companion.HIGHEST_PAGE_SIZE_EXPONENT
import com.bloomberg.selekt.android.SQLiteOpenParams.Companion.LOWEST_PAGE_SIZE_EXPONENT
import org.junit.jupiter.api.Test
import java.lang.IllegalArgumentException
import kotlin.test.assertFailsWith

internal class SQLiteOpenParamsTest {
    @Test
    fun excessivePageSizeExponent() {
        assertFailsWith<IllegalArgumentException> {
            SQLiteOpenParams(pageSizeExponent = HIGHEST_PAGE_SIZE_EXPONENT + 1)
        }
    }

    @Test
    fun deficientPageSizeExponent() {
        assertFailsWith<IllegalArgumentException> {
            SQLiteOpenParams(pageSizeExponent = LOWEST_PAGE_SIZE_EXPONENT - 1)
        }
    }
}
