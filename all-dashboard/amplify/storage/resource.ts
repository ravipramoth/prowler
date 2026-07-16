import { defineStorage } from "@aws-amplify/backend";

export const storage = defineStorage({
  name: "sentinelScopeScans",
  access: (allow) => ({
    "scans/{entity_id}/*": [
      allow.entity("identity").to(["read", "write", "delete"]),
    ],
  }),
});
