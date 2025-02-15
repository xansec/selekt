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

package com.bloomberg.selekt.pools

import org.junit.jupiter.api.Test
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.same
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever

internal class TieredObjectPoolTest {
    private val singleObjectPool: SingleObjectPool<String, PooledObject> = mock()
    private val commonObjectPool: CommonObjectPool<String, PooledObject> = mock()
    private val pool = TieredObjectPool(singleObjectPool, commonObjectPool)

    @Test
    fun borrowPrimaryObject() {
        pool.borrowPrimaryObject()
        verify(singleObjectPool, times(1)).borrowObject()
        verifyNoInteractions(commonObjectPool)
    }

    @Test
    fun borrowSecondaryObjectKeyed() {
        val key = ""
        pool.borrowObject(key)
        verifyNoInteractions(singleObjectPool)
        verify(commonObjectPool, times(1)).borrowObject(same(key))
    }

    @Test
    fun borrowSecondaryObject() {
        pool.borrowObject()
        verifyNoInteractions(singleObjectPool)
        verify(commonObjectPool, times(1)).borrowObject()
    }

    @Test
    fun close() {
        pool.close()
        verify(singleObjectPool, times(1)).close()
        verify(commonObjectPool, times(1)).close()
    }

    @Test
    fun returnPrimaryObject() {
        val obj = mock<PooledObject>().apply {
            whenever(isPrimary) doReturn true
        }
        pool.returnObject(obj)
        verify(singleObjectPool, times(1)).returnObject(same(obj))
        verifyNoInteractions(commonObjectPool)
    }

    @Test
    fun returnObject() {
        val obj = mock<PooledObject>().apply {
            whenever(isPrimary) doReturn false
        }
        pool.returnObject(obj)
        verify(commonObjectPool, times(1)).returnObject(same(obj))
        verifyNoInteractions(singleObjectPool)
    }

    @Test
    fun clearsAllPools() {
        val priority = Priority.HIGH
        pool.clear(priority)
        verify(singleObjectPool, times(1)).clear(same(priority))
        verify(commonObjectPool, times(1)).clear(same(priority))
    }
}
