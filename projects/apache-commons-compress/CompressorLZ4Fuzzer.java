// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream;
import org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class CompressorLZ4Fuzzer extends BaseTests {
    // Test both LZ4 classes
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            fuzzCompressorInputStream(new BlockLZ4CompressorInputStream(new ByteArrayInputStream(data)));
        } catch (IOException ignored) {
        }

        try {
            fuzzCompressorInputStream(new FramedLZ4CompressorInputStream(new ByteArrayInputStream(data)));
        } catch (IOException ignored) {
        }
    }
}