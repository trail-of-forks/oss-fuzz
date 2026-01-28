/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core.h"
#include "topo.h"
#include "xml.h"

typedef ncclResult_t (*xmlHandlerFunc_t)(FILE*, struct ncclXml*, struct ncclXmlNode*);
struct xmlHandler {
  const char * name;
  xmlHandlerFunc_t func;
};

ncclResult_t xmlLoadSub(FILE* file, struct ncclXml* xml, struct ncclXmlNode* head, struct xmlHandler handlers[], int nHandlers);
ncclResult_t ncclTopoXmlLoadSystem(FILE* file, struct ncclXml* xml, struct ncclXmlNode* head);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10 || size > 50000) return 0;

  // Use fmemopen to create a FILE* from memory, avoiding disk I/O
  FILE *fp = fmemopen((void *)data, size, "r");
  if (!fp) {
    return 0;
  }

  struct ncclXml *xml = nullptr;
  if (xmlAlloc(&xml, NCCL_TOPO_XML_MAX_NODES) != ncclSuccess) {
    fclose(fp);
    return 0;
  }

  // Parse directly from memory stream (same logic as ncclTopoGetXmlFromFile)
  struct xmlHandler handlers[] = { { "system", ncclTopoXmlLoadSystem } };
  xml->maxIndex = 0;
  xmlLoadSub(fp, xml, NULL, handlers, 1);

  free(xml);
  fclose(fp);

  return 0;
}
