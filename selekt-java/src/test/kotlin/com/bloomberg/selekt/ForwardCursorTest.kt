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

package com.bloomberg.selekt

import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

internal class ForwardCursorTest {
    @Test
    fun columnIndex() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar", "xyz")
        }
        assertEquals(1, ForwardCursor(statement).columnIndex("xyz"))
    }

    @Test
    fun columnName() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        assertEquals("bar", ForwardCursor(statement).columnName(0))
    }

    @Test
    fun columnNames() {
        val columns = arrayOf("bar")
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn columns
        }
        assertSame(columns, ForwardCursor(statement).columnNames())
    }

    @Test
    fun countIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).count
        }
    }

    @Test
    fun getBlob() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        ForwardCursor(statement).getBlob(0)
        verify(statement, times(1)).columnBlob(eq(1))
    }

    @Test
    fun getDouble() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        ForwardCursor(statement).getDouble(0)
        verify(statement, times(1)).columnDouble(eq(1))
    }

    @Test
    fun getInt() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        ForwardCursor(statement).getInt(0)
        verify(statement, times(1)).columnInt(eq(1))
    }

    @Test
    fun getLong() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        ForwardCursor(statement).getLong(0)
        verify(statement, times(1)).columnLong(eq(1))
    }

    @Test
    fun getShort() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        ForwardCursor(statement).getInt(0)
        verify(statement, times(1)).columnInt(eq(1))
    }

    @Test
    fun getString() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        ForwardCursor(statement).getString(0)
        verify(statement, times(1)).columnString(eq(1))
    }

    @Test
    fun isAfterLastIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).isAfterLast()
        }
    }

    @Test
    fun isBeforeFirstIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).isBeforeFirst()
        }
    }

    @Test
    fun close() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }
        val cursor = ForwardCursor(statement)
        assertFalse(cursor.isClosed())
        cursor.close()
        assertTrue(cursor.isClosed())
        verify(statement, times(1)).close()
    }

    @Test
    fun isNotClosed() {
        assertFalse(ForwardCursor(mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
        }).isClosed())
    }

    @Test
    fun isFirstIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).isFirst()
        }
    }

    @Test
    fun isLastIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).isLast()
        }
    }

    @Test
    fun isNull() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
            whenever(columnType(any())) doReturn ColumnType.NULL.sqlDataType
        }
        assertTrue(ForwardCursor(statement).isNull(0))
        verify(statement, times(1)).columnType(eq(1))
    }

    @Test
    fun isNotNull() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
            whenever(columnType(any())) doReturn ColumnType.STRING.sqlDataType
        }
        assertFalse(ForwardCursor(statement).isNull(0))
        verify(statement, times(1)).columnType(eq(1))
    }

    @Test
    fun moveIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).move(1)
        }
    }

    @Test
    fun moveToFirstIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).moveToFirst()
        }
    }

    @Test
    @Suppress("Detekt.CognitiveComplexMethod")
    fun moveToNext() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
            var stepCount = 0
            whenever(step()) doAnswer Answer<SQLDataType> {
                if (stepCount++ < 1) {
                    SQL_ROW
                } else {
                    SQL_DONE
                }
            }
            whenever(columnType(any())) doAnswer Answer<SQLDataType> {
                if (stepCount == 1) {
                    SQL_TEXT
                } else {
                    error("No type available.")
                }
            }
            whenever(columnString(any())) doAnswer Answer<String> {
                if (stepCount == 1 && requireNotNull(it.getArgument(0) as? Int) == 1) {
                    "abc"
                } else {
                    error("No type available.")
                }
            }
        }
        ForwardCursor(statement).apply {
            assertTrue(moveToNext())
            assertEquals("abc", getString(0))
            assertFalse(moveToNext())
        }
    }

    @Test
    fun type() {
        val statement = mock<SQLPreparedStatement>().apply {
            whenever(columnNames) doReturn arrayOf("bar")
            whenever(columnType(any())) doReturn ColumnType.NULL.sqlDataType
        }
        assertEquals(ColumnType.NULL, ForwardCursor(statement).type(0))
        verify(statement, times(1)).columnType(eq(1))
    }

    @Test
    fun moveToPositionIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).moveToPosition(0)
        }
    }

    @Test
    fun moveToPreviousIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).moveToPrevious()
        }
    }

    @Test
    fun moveToLastIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).moveToLast()
        }
    }

    @Test
    fun positionIsUnsupported() {
        assertFailsWith<UnsupportedOperationException> {
            ForwardCursor(mock<SQLPreparedStatement>().apply {
                whenever(columnNames) doReturn arrayOf("bar")
            }).position()
        }
    }
}
