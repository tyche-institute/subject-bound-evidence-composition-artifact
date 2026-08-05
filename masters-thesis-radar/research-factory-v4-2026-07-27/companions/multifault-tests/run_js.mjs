#!/usr/bin/env node
/* Execute the frozen JS mutation evaluator against this directory's packet. */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const sourcePath = path.join(
  here,
  "../mutation-tests/evaluate_mutation_corpus.mjs",
);
let source = fs.readFileSync(sourcePath, "utf8");
source = source.replace(
  "const here = path.dirname(fileURLToPath(import.meta.url));",
  `const here = ${JSON.stringify(here)};`,
);
source = source.replace(
  'const packetPath = path.join(here, "mutation-packet.json");',
  'const packetPath = path.join(here, "multifault-packet.json");',
);
source = source.replaceAll("mutation-js-v1", "multifault-js-v1");
await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
