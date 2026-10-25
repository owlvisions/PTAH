import {
  schemaArrays,
  schemaChildren,
  schemaMaps,
} from "../../src/contracts/jsonSchemaKeywords.js";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** VS Code Copilot rejects falsy `items` for any type that admits arrays. */
export const arrayItemSchemaError = (
  schema: unknown,
  path: string,
): string | undefined => {
  if (!isRecord(schema)) return undefined;
  const admitsArrays =
    schema.type === "array" ||
    (Array.isArray(schema.type) && schema.type.includes("array"));
  if (admitsArrays && !schema.items)
    return `${path}: tool parameters array type must have items`;
  for (const [key, value] of Object.entries(schema)) {
    const children =
      schemaMaps.has(key) && isRecord(value)
        ? Object.entries(value).map(
            ([name, child]) => [`${key}.${name}`, child] as const,
          )
        : (schemaArrays.has(key) || schemaChildren.has(key)) &&
            Array.isArray(value)
          ? value.map(
              (child: unknown, index) => [`${key}.${index}`, child] as const,
            )
          : schemaChildren.has(key)
            ? [[key, value] as const]
            : [];
    for (const [suffix, child] of children) {
      const error = arrayItemSchemaError(child, `${path}.${suffix}`);
      if (error !== undefined) return error;
    }
  }
  return undefined;
};

/** Reject Gemini-incompatible boolean and empty-string input literals. */
export const unsupportedInputLiteralSchemaError = (
  schema: unknown,
  path: string,
): string | undefined => {
  if (!isRecord(schema)) return undefined;
  if (typeof schema.const === "boolean") return `${path}.const is boolean`;
  if (schema.const === "") return `${path}.const is an empty string`;
  if (
    Array.isArray(schema.enum) &&
    schema.enum.some((value) => typeof value === "boolean")
  )
    return `${path}.enum contains a boolean`;
  if (Array.isArray(schema.enum) && schema.enum.includes(""))
    return `${path}.enum contains an empty string`;
  for (const [key, value] of Object.entries(schema)) {
    const children =
      schemaMaps.has(key) && isRecord(value)
        ? Object.entries(value).map(
            ([name, child]) => [`${key}.${name}`, child] as const,
          )
        : schemaArrays.has(key) && Array.isArray(value)
          ? value.map(
              (child: unknown, index) => [`${key}[${index}]`, child] as const,
            )
          : schemaChildren.has(key)
            ? [[key, value] as const]
            : [];
    for (const [suffix, child] of children) {
      const error = unsupportedInputLiteralSchemaError(
        child,
        `${path}.${suffix}`,
      );
      if (error !== undefined) return error;
    }
  }
  return undefined;
};

/**
 * Gemini function declarations accept `items` only on a schema whose type is
 * the single `array` type (`items: field predicate failed: $type ==
 * Type.ARRAY`), and strict gateways drop untyped item unions. Return every
 * advertised position with either shape so a catalog test names them all.
 */
export const strictGatewayItemSchemaErrors = (
  schema: unknown,
  path = "$",
): readonly string[] => {
  if (!isRecord(schema)) return [];
  const here: string[] = [];
  if (schema.items !== undefined && schema.type !== "array")
    here.push(`${path}.items is beside type ${JSON.stringify(schema.type)}`);
  const items = schema.items;
  if (
    schema.type === "array" &&
    isRecord(items) &&
    items.type === undefined &&
    (Array.isArray(items.oneOf) || Array.isArray(items.anyOf))
  )
    here.push(`${path}.items is an untyped union`);
  return [
    ...here,
    ...Object.entries(schema).flatMap(([key, value]) => {
      if (schemaMaps.has(key) && isRecord(value))
        return Object.entries(value).flatMap(([name, child]) =>
          strictGatewayItemSchemaErrors(child, `${path}.${key}.${name}`),
        );
      if (schemaArrays.has(key) && Array.isArray(value))
        return value.flatMap((child: unknown, index) =>
          strictGatewayItemSchemaErrors(child, `${path}.${key}[${index}]`),
        );
      if (schemaChildren.has(key))
        return Array.isArray(value)
          ? value.flatMap((child: unknown, index) =>
              strictGatewayItemSchemaErrors(child, `${path}.${key}[${index}]`),
            )
          : strictGatewayItemSchemaErrors(value, `${path}.${key}`);
      return [];
    }),
  ];
};
