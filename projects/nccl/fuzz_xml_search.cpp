#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "core.h"
#include "xml.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20 || size > 50000) return 0;
  
  char filename[256];
  sprintf(filename, "/tmp/fuzz_xml_node_%d.xml", getpid());
  
  FILE *fp = fopen(filename, "wb");
  if (!fp) return 0;
  
  fwrite(data, size, 1, fp);
  fclose(fp);
  
  struct ncclXml *xml;
  ncclCalloc(&xml, 1);
  
  // Parse XML and test node operations
  if (ncclTopoGetXmlFromFile(filename, xml, 0) == ncclSuccess) {
    // Traverse XML nodes with fuzzed indices
    int nodeIndex = data[0] % 100;
    struct ncclXmlNode *node = ncclXmlFindTag(xml, "system");
    if (node) {
      ncclXmlGetAttr(node, "name", NULL);
    }
  }
  
  free(xml);
  unlink(filename);
  return 0;
}