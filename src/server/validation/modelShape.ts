interface Constrained {
  min?: number;
  max?: number;
  sensitive?: boolean;
}

export type ModelShape =
  | ({
      type: "structure";
      members: Record<string, string>;
      required?: string[];
    } & Constrained)
  | ({ type: "list"; member: string } & Constrained)
  | ({ type: "map"; key: string; value: string } & Constrained)
  | ({ type: "string"; pattern?: string; enum?: string[] } & Constrained)
  | ({ type: "integer" | "long" | "blob" } & Constrained)
  | ({ type: "boolean" | "timestamp" | "document" } & Constrained);
