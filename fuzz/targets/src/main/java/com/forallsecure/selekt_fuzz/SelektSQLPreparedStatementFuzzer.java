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

package com.forallsecure.selekt_fuzz;

import com.bloomberg.selekt.IRandom;
import com.bloomberg.selekt.SQLPreparedStatement;
import com.bloomberg.selekt.SQLite;
import static org.mockito.Mockito.*;
//import org.mockito.kotlin.any
//import org.mockito.kotlin.doAnswer
//import org.mockito.kotlin.doReturn
//import org.mockito.kotlin.eq
//import org.mockito.kotlin.mock
//import org.mockito.kotlin.times
//import org.mockito.kotlin.verify
//import org.mockito.kotlin.whenever
//import org.mockito.stubbing.Answer
//import kotlin.test.assertEquals
//import kotlin.test.assertFailsWith
//import kotlin.test.assertFalse
//import kotlin.test.assertTrue
import com.code_intelligence.jazzer.api.FuzzedDataProvider;


public class SelektSQLPreparedStatementFuzzer {

  private static final long POINTER = 42L;
  private static final int MAX = 86400;

  abstract static class CTLR implements IRandom {
  }

  static class MyCTLR extends CTLR {
    @Override
    public long nextLong(long bound) {
      return bound + 1;
    }
  }


  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String fsql = data.consumeString(MAX);
    Integer fint = data.consumeInt();
    IRandom FuzzCTLR = new MyCTLR();
    SQLite mydb = mock(SQLite.class);
    SQLPreparedStatement mystatement = new SQLPreparedStatement(POINTER, fsql, mydb, FuzzCTLR);
    mystatement.bind(fint, data.consumeRemainingAsBytes());
  }

}

