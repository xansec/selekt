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

import com.bloomberg.selekt.SQLDatabase
import com.bloomberg.selekt.commons.deleteDatabase
import java.io.File

internal fun <R> SQLiteDatabase.destroy(block: (SQLiteDatabase) -> R): R = try {
    use(block)
} finally {
    deleteDatabase(File(path))
}

internal fun <R> SQLDatabase.destroy(block: (SQLDatabase) -> R): R = try {
    use(block)
} finally {
    deleteDatabase(File(path))
}
