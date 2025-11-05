declare module "tap-diff" {
  import type { Transform } from "node:stream";
  function tapDiff(): Transform;
  export = tapDiff;
}
